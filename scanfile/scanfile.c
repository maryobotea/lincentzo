#include "scanfile.h"
#include "../antiviRus/antiviRus.h"
#include "../utils/utils.h"
#include <math.h>

#define LN2 0.693147180559945309417

static inline double fast_log2(double x) {
    if (x <= 0) return 0;
    return log(x) / LN2;
}

double calculate_entropy(int8* data, int32 size) {
    // 1. Filtru de relevanță: Secțiunile prea mici nu au relevanță statistică
    if (size < 256) return 0.0;

    int32 counts[256] = {0};
    int32 total_samples = 0;
    int32 step;

    if (size > 65536) {
        step = 16 * size  / 65536;
    } else {
        step = 1; 
    }

    for (int32 i = 0; i < size; i += step) {
        counts[data[i]]++;
        total_samples++;
    }

    double entropy = 0.0;
    double inv_samples = 1.0 / (double)total_samples;

    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] * inv_samples;
            entropy -= p * fast_log2(p);
        }
    }

    return entropy;
}

static int32 rva_to_offset(IMAGE_SECTION_HEADER* sec, int32 numSections, int32 rva) {
    for (int i = 0; i < numSections; i++) {
        if (rva >= sec[i].VirtualAddress && rva < (sec[i].VirtualAddress + sec[i].Misc.VirtualSize)) {
            return (rva - sec[i].VirtualAddress) + sec[i].PointerToRawData;
        }
    }
    return -1;
}

static void check_trailing_dots_imports(unsigned char* pFile, IMAGE_NT_HEADERS* nt, ScanReport* r, int32 fileSize) {
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    int32 numSections = nt->FileHeader.NumberOfSections;

    int32 importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) return;

    int32 importOffset = rva_to_offset(sec, numSections, importRVA);
    if (importOffset == -1 || 
        importOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return;

    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(pFile + importOffset);

    int32 count = 0;
    while (imp->Name != 0 && count < 256) {
        // Bounds check inainte de orice acces
        if ((unsigned char*)imp + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pFile + fileSize) break;

        int32 nameOffset = rva_to_offset(sec, numSections, imp->Name);
        if (nameOffset == -1 || nameOffset >= fileSize) {
            imp++;
            count++;
            continue;
        }

        // Citim numele DLL-ului
        int8* dllName = (int8*)(pFile + nameOffset);

        // Calculam lungimea cu limita de siguranta
        int32 nameLen = 0;
        while (nameLen < 256 && nameOffset + nameLen < fileSize && dllName[nameLen] != 0)
            nameLen++;

        // Verificam daca numele se termina cu punct
        // kernel32.dll... = tehnica de evazie — loader-ul ignora punctele
        // dar heuristicile statice pot rata importul
        if (nameLen > 0 && dllName[nameLen - 1] == '.') {
            r->flags |= ANOMALY_TRAILING_DOTS;
            r->totalScore += 50;
            return; // Un singur DLL cu trailing dots e suficient
        }

        imp++;
        count++;
    }
}

// Verifică malformații în Optional Header (Win32Version, EntryPoint, Alignment)
static void check_header_malformations(int8 * pFile, IMAGE_NT_HEADERS* nt, ScanReport* r) {

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pFile;
    // 1. Win32VersionValue — rezervat, trebuie sa fie 0
    // Daca e setat, malware-ul suprascrie informatii de versiune din PEB
    // Folosit pentru a sparge emulatori care citesc versiunea din header
    if (nt->OptionalHeader.Win32VersionValue != 0)
        r->totalScore += 40;

    // 2. AddressOfEntryPoint == 0 pe EXE
    // Pe DLL e legitim, pe EXE inseamna executie de la ImageBase
    // MZ = 'dec ebp / pop edx' — valid tehnic dar foarte suspect
    int32 isDLL = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
    if (nt->OptionalHeader.AddressOfEntryPoint == 0 && !isDLL)
        r->totalScore += 50;

    // 3. FileAlignment invalid
    // Trebuie sa fie putere a lui 2 si minim 512
    // Daca nu e, loader-ul se comporta impredictibil
    int32 fAlign = nt->OptionalHeader.FileAlignment;
    if (fAlign < 512 || (fAlign & (fAlign - 1)) != 0)
        r->totalScore += 30;

    // 4. NumberOfSections invalid
    // 0 sectiuni = sectionless PE (Tiny PE trick)
    // > 96 = depaseste spec-ul, crashuie unele parsere
    int32 numSections = nt->FileHeader.NumberOfSections;
    if (numSections == 0 || numSections > 96)
        r->totalScore += 40;

    // 5. SectionAlignment invalid
    int32 sAlign = nt->OptionalHeader.SectionAlignment;

    // SectionAlignment trebuie sa fie >= FileAlignment
    if (sAlign < fAlign)
        r->totalScore += 30;

    // Daca SectionAlignment < 4096 si != FileAlignment = nu e in low-alignment mode corect
    if (sAlign < 4096 && sAlign != fAlign)
        r->totalScore += 25;

    // SectionAlignment trebuie sa fie putere a lui 2
    if (sAlign != 0 && (sAlign & (sAlign - 1)) != 0)
        r->totalScore += 30;

    // 6. SizeOfImage nealiniat la SectionAlignment
    // Windows loader refuza sa incarce fisierul daca nu e aliniat
    // Daca totusi ruleaza, loader-ul a corectat valoarea = comportament nedocumentat
    if (sAlign != 0 && nt->OptionalHeader.SizeOfImage % sAlign != 0)
        r->totalScore += 25;

    // 7. Dual PE Header
    // Calculam dimensiunea minima reala a header-ului:
    // DOS Header + NT Headers + Section Table
    int32 minHeaderSize = dos->e_lfanew                          // offset la NT Headers
        + sizeof(DWORD)                                          // PE signature
        + sizeof(IMAGE_FILE_HEADER)                              // COFF Header
        + nt->FileHeader.SizeOfOptionalHeader                    // Optional Header
        + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER); // Section Table

    // Daca SizeOfHeaders e mai mic decat minimul real = Dual PE Header trick
    // Header-ul din memorie e diferit de cel de pe disc
    // Tools statice vad alte importuri/exporturi decat cele folosite la runtime
    if (nt->OptionalHeader.SizeOfHeaders < minHeaderSize) {
        r->totalScore += 60;
    }

    // 8. ImageBase invalid
    // Zero = loader-ul rebazeza la 0x10000, sparge emulatori
    // Nu e multiplu de 0x10000 = malformatie clara
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    // Pe PE64 ImageBase poate fi mult mai mare — doar verificam alinierea
        if (nt->OptionalHeader.ImageBase % 0x10000 != 0)
            r->totalScore += 30;
    } else {
        // Pe PE32 ImageBase > 0x80000000 = rebazare fortata
        if (nt->OptionalHeader.ImageBase == 0 ||
            nt->OptionalHeader.ImageBase % 0x10000 != 0)
            r->totalScore += 30;

        if (nt->OptionalHeader.ImageBase + nt->OptionalHeader.SizeOfImage >= 0x80000000)
            r->totalScore += 30;
    }

    // 9. Arhitectura contradictorie
    // I386 (32-bit) cu Optional Header de 64-bit = imposibil legitim
    // Sparge parsere care aleg modul de parsare bazat pe Machine sau Magic
    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
        nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        r->totalScore += 60;

    // 10. Subsystem invalid
    // 0 = nedefinit, > 14 = valoare necunoscuta
    // Unele emulatori refuza sa ruleze fisiere cu subsystem invalid
    int32 subsys = nt->OptionalHeader.Subsystem;
    if (subsys == 0 || subsys > 14)
        r->totalScore += 25;

    // 11. NumberOfRvaAndSizes != 16
    // Spec-ul spune ca trebuie sa fie 16
    // Daca e mai mic, unele DataDirectory entries sunt ascunse de parsere
    // Daca e mai mare, parsere pot citi memorie invalida
    if (nt->OptionalHeader.NumberOfRvaAndSizes != 16)
        r->totalScore += 25;

    // 12. IMAGE_FILE_DLL si IMAGE_FILE_EXECUTABLE_IMAGE setate simultan = contradictie
    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
        (nt->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
        r->totalScore += 30;

    // 13. IMAGE_FILE_32BIT_MACHINE pe un PE64 = contradictie arhitectura
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        (nt->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE))
        r->totalScore += 40;

    // 14. RVA != 0 dar Size == 0 = structura prezenta dar fara dimensiune declarata
    // Parsere pot sari structura, loader-ul o citeste oricum
    // Tehnica pentru a ascunde importuri/exporturi de analizoare statice
    for (int i = 0; i < 16; i++) {
    int32 rva  = nt->OptionalHeader.DataDirectory[i].VirtualAddress;
    int32 size = nt->OptionalHeader.DataDirectory[i].Size;

    if (rva != 0 && size == 0)
        r->totalScore += 30;

    if (rva == 0 && size != 0)
        r->totalScore += 30;
    }

    // 15. SizeOfImage trebuie sa fie cel putin cat ultima sectiune + VirtualAddress
    // Daca e mai mic, loader-ul corecteaza dar parsere pot esua
    int32 lastVA = 0;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        int32 end = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
        if (end > lastVA) lastVA = end;
    }
    if (nt->OptionalHeader.SizeOfImage < lastVA)
        r->totalScore += 40;

    //16. SizeOfOptionalHeader prea mic = Collapsed Optional Header
    // Section Table se suprapune cu Optional Header
    // Tools nu pot parsa DataDirectory, importuri, exporturi
    int32 sizeOfOptHeader = nt->FileHeader.SizeOfOptionalHeader;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // PE64 — marimea normala e 240 bytes
        if (sizeOfOptHeader < sizeof(IMAGE_OPTIONAL_HEADER64) || sizeOfOptHeader > sizeof(IMAGE_OPTIONAL_HEADER64))
            r->totalScore += 50;
    } else {
        // PE32 — marimea normala e 224 bytes
        if (sizeOfOptHeader < sizeof(IMAGE_OPTIONAL_HEADER32) || sizeOfOptHeader > sizeof(IMAGE_OPTIONAL_HEADER32))
            r->totalScore += 50;
    }

    //17. Writeable PE File Header
    if (fAlign == sAlign && fAlign <= 0x200 && fAlign > 0) {
        r->totalScore += 40;
    }

    // 18. Exporturi vs DLL flag
    int32 hasExports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0;

    // Exporturi fara flag DLL — posibil compilator vechi, scor mic
    if (hasExports && !isDLL)
        r->totalScore += 20;

    // DLL fara exporturi — poate fi DLL de resurse, scor foarte mic
    if (!hasExports && isDLL)
        r->totalScore += 10;

}

// Verifică anomaliile la nivel de secțiune (RWE, Inflation)
static void check_section_anomalies(unsigned char* pFile, IMAGE_NT_HEADERS* nt, ScanReport * r, int32 fileSize) {
    int numSections = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    int32 ep = nt->OptionalHeader.AddressOfEntryPoint;
    int32 fAlign = nt->OptionalHeader.FileAlignment;
    int32 sAlign = nt->OptionalHeader.SectionAlignment;
    int32 epFound = 0;
    int32 execSections = 0;
    int32 readableSections = 0;

    for (int i = 0; i < numSections; i++) {
        int32 vSize = sec[i].Misc.VirtualSize;
        int32 rSize = sec[i].SizeOfRawData;
        int32 pRaw  = sec[i].PointerToRawData;
        int32 charact = sec[i].Characteristics;

        // --- A. RWE ---
        if ((charact & IMAGE_SCN_MEM_EXECUTE) && (charact & IMAGE_SCN_MEM_WRITE))
            r->flags |= ANOMALY_RWE;

        // --- B. Nume Suspicios ---
        int32 hasBinaryChars = 0, hasBadNull = 0, foundNull = 0;
        int32 allSame = 1;
        int8 first = sec[i].Name[0];

        for (int32 k = 0; k < 8; k++) {
            int8 c = sec[i].Name[k];

            if (c == 0)            { foundNull = 1; continue; }
            if (foundNull)           hasBadNull     = 1;
            if (c < 32 || c > 126)  hasBinaryChars = 1;
            if (c != first)          allSame        = 0;
        }

        if (hasBinaryChars || hasBadNull) {
            r->flags |= ANOMALY_SUSP_NAME;
            r->totalScore += 80;
        } else if (allSame && first != 0) {
            //Scor mic, dar e totuși suspect ca toate caracterele să fie la fel (ex: "AAAAAAAA") - unele packere fac asta intenționat pentru a îngreuna analiza
        } else if (first == 0 && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            r->totalScore += 15;
            //Scor mic, dar e totuși suspect ca o secțiune executabilă să nu aibă nume (deși unele packere fac asta intenționat pentru a îngreuna analiza)
        }

        // --- C. Hidden Disk Data (RSize > VSize) ---
        if (rSize > vSize) {
        int32 diff = rSize - vSize;

            if (diff > 8) {
                if (diff > 4096) {
                    // Cavitate uriasa = malware direct, nu mai scanam
                    r->flags |= ANOMALY_HIDDEN_D_DISC;
                    r->totalScore += 80;
                } else {
                    // Cavitate mica — scanam fiecare byte
                    int8* caveStart = pFile + pRaw + vSize;
                    for (int32 j = 0; j < diff; j++) {
                        if (caveStart[j] != 0x00 && caveStart[j] != 0x90 && caveStart[j] != 0xCC) {
                            r->flags |= ANOMALY_HIDDEN_D_DISC;
                            r->totalScore += 80;
                            break;
                        }
                    }
                }
            }
        }

        // --- D. EntryPoint in Cave ---
        // Verificăm dacă EP cade între VirtualEnd și RawEnd
        int32 epInCave;

        if (vSize == 0) {
            // Sectiunea nu are spatiu virtual deloc — toata zona raw e "cavitate"
            // Orice EP care cade intre inceputul sectiunii si sfarsitul datelor raw e suspect
            epInCave = (ep >= sec[i].VirtualAddress && ep < sec[i].VirtualAddress + rSize);
        } else {
            // Sectiunea are spatiu virtual valid [VirtualAddress, VirtualAddress + vSize)
            // Verificam daca EP cade DUPA zona virtuala legitima dar INAINTE de sfarsitul raw
            // Aceasta zona exista pe disc dar nu e niciodata incarcata in memorie de Windows loader
            // Un program legitim nu poate avea EP aici — prin definitie e malware
            epInCave = (ep > sec[i].VirtualAddress + vSize && ep < sec[i].VirtualAddress + rSize);
        }

        if (epInCave) {
            r->flags |= ANOMALY_EP_IN_CAVE;
            //scor mare, deoarece un EP care cade într-o cavitate pe disc e un indiciu foarte puternic de cod generat dinamic (ex: shellcode injectat în memorie sau secțiune creată dinamic de un packer)
        }

        // --- E. Entropie ---
        // Cazul vSize == 0 verificat INDEPENDENT de SizeOfRawData/PointerToRawData
        if (vSize == 0 && (charact & IMAGE_SCN_MEM_EXECUTE)) {
            if (!(r->flags & ANOMALY_EMPTY_SEC)) 
                r->flags |= ANOMALY_EMPTY_SEC;
            //scor mare, deoarece o secțiune executabilă fără spațiu virtual e un indiciu foarte puternic de cod generat dinamic (ex: shellcode injectat în memorie sau secțiune creată dinamic de un packer)
        }

        if (sec[i].SizeOfRawData == 0 || sec[i].PointerToRawData == 0) {

            // Sectiune executabila fara date pe disc
            if (sec[i].SizeOfRawData == 0 && (charact & IMAGE_SCN_MEM_EXECUTE)) {
                r->flags |= ANOMALY_EMPTY_SEC;
                //scor mare, deoarece o secțiune executabilă fără date pe disc e un indiciu foarte puternic de cod generat dinamic (ex: shellcode injectat în memorie sau secțiune creată dinamic de un packer)
            }

            // PointerToRawData == 0 dar SizeOfRawData > 0 = malformatie structurala
            if (sec[i].PointerToRawData == 0 && sec[i].SizeOfRawData > 0) {
                //scor mediu, deoarece e o malformație structurală care poate fi cauzată de un packer prost sau de coruperea intenționată a fișierului pentru a împiedica analiza
            }

            // EP intr-o sectiune fara date pe disc
            if (ep >= sec[i].VirtualAddress &&
                ep < sec[i].VirtualAddress + sec[i].Misc.VirtualSize &&
                sec[i].SizeOfRawData == 0) {
                r->flags |= ANOMALY_EP_IN_0_SEC;
                //scor foarte mare, deoarece un EP care cade într-o secțiune fără date pe disc e un indiciu foarte puternic de cod generat dinamic (ex: shellcode injectat în memorie sau secțiune creată dinamic de un packer)
            }

        } else {
            double h = calculate_entropy(pFile + sec[i].PointerToRawData, sec[i].SizeOfRawData);
            
            if (h > 7.2 && (charact & IMAGE_SCN_MEM_EXECUTE)) {
                // Cod executabil criptat - 7.2 e suficient de strict
                r->flags |= ANOMALY_HIGH_ENTROPY;
                //scor mare, deoarece codul executabil cu entropie foarte mare e un indiciu puternic de cod generat dinamic sau criptat (ex: shellcode injectat în memorie sau secțiune creată dinamic de un packer)
            } else if (h > 7.8 && !(charact & IMAGE_SCN_MEM_EXECUTE)) {
                // Date cu entropie EXTREM de mare - 7.8 elimina practic orice date legitime comprimate
                r->flags |= ANOMALY_HIGH_ENTROPY;
                if (r->flags & ANOMALY_SUSP_NAME)
                    r->totalScore += 50; // Bonus de coroborare a dovezilor
                    //scor mediu 
                else
                    r->totalScore += 30;
            }
        }


        // --- F. Inflation (VSize > RSize) ---
        if (rSize > 0) {  
            int32 ratio = vSize / rSize;

            if (ratio > 3) {
                // Sectiune de COD cu inflation
                if (charact & IMAGE_SCN_MEM_EXECUTE) {
                    r->flags |= ANOMALY_INFLATION;
                    if (ratio > 10) {
                        r->totalScore += 70;
                    } else {
                        r->totalScore += 40;
                    }
                    // ratio > 10 = self-modifying/packer aproape sigur
                    // ratio 3-10 = suspect dar posibil legitim
                }
                // Sectiune de DATE/RESURSE
                else if (ratio > 20) {
                    // Program legitim poate decomprima date in RAM
                    // Dar >20x e aproape cert process hollowing target
                    r->flags |= ANOMALY_INFLATION;
                    r->totalScore += 50;
                }
            }

            // Coroborare — inflation + nume suspect = cert intentional
            if ((r->flags & ANOMALY_INFLATION) && (r->flags & ANOMALY_SUSP_NAME))
                r->totalScore += 30;
        }

        // --- G. EP Outside Sections ---
        if (ep >= sec[i].VirtualAddress && ep < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            epFound = 1;
        }
        
        // --- H. Numar sectiuni executabile ---
        if (charact & IMAGE_SCN_MEM_EXECUTE) execSections++;

        // --- I. Sectiune dincolo de EOF ---
        // O sectiune care pretinde ca are date dincolo de EOF = malformatie intentionata
        // Sparge parsere care citesc bazat pe SizeOfRawData si poate ascunde date
        if (pRaw != 0 && rSize != 0 && (pRaw + rSize) > fileSize) {
            r->flags |= ANOMALY_SEC_BEYOND_EOF;
        }

        // --- J. PointerToRawData nealiniat la FileAlignment ---
        // Spec-ul spune ca PointerToRawData trebuie sa fie multiplu de FileAlignment
        // Daca nu e, e fie malformatie accidentala fie intentionata pentru a confuza parsere
        if (pRaw != 0 && fAlign != 0 && (pRaw % fAlign) != 0) {
            r->flags |= ANOMALY_UNALIGNED_SEC;
        }

        // --- K. VirtualAddress nealiniat la SectionAlignment ---
        // Similar cu J dar pentru spatiul virtual
        // Loader-ul Windows poate corecta asta, dar e totusi o malformatie clara
        if (sAlign != 0 && (sec[i].VirtualAddress % sAlign) != 0) {
            r->flags |= ANOMALY_UNALIGNED_SEC;
        }

        // --- L. Sectiuni suprapuse in memoria virtuala ---
        // Doua sectiuni nu ar trebui sa se suprapuna in spatiul virtual
        // Malware face asta pentru a confuza parsere si a ascunde cod sub o alta sectiune
        if (i < numSections - 1) {
            // Suprapunere pe disc
            int32 currentRawEnd = pRaw + rSize;
            if (currentRawEnd > sec[i+1].PointerToRawData)
                r->flags |= ANOMALY_SEC_OVERLAP;

            // Suprapunere in memorie virtuala — lipseste
            int32 currentVEnd = sec[i].VirtualAddress + vSize;
            if (currentVEnd > sec[i+1].VirtualAddress)
                r->flags |= ANOMALY_SEC_OVERLAP;
        }


        // --- M. Sectiune citibila ---
        if (charact & IMAGE_SCN_MEM_READ) readableSections++;


        // --- N. Sectiune in interiorul header-ului PE ---
        // PointerToRawData mai mic decat SizeOfHeaders inseamna ca
        // datele sectiunii incep in interiorul header-ului PE
        // Dual PE Header trick — header-ul de pe disc e diferit de cel din memorie
        if (pRaw != 0 && pRaw < nt->OptionalHeader.SizeOfHeaders) {
            r->flags |= ANOMALY_SEC_IN_HEADER;
        }

        // --- O. Sectiune in interiorul header-ului PE ---
        // PointerToRawData mai mic decat SizeOfHeaders inseamna ca
        // datele sectiunii incep in interiorul header-ului PE
        // Dual PE Header trick — header-ul de pe disc e diferit de cel din memorie
        if (pRaw != 0 && pRaw < nt->OptionalHeader.SizeOfHeaders) {
            r->flags |= ANOMALY_SEC_IN_HEADER;

            // Daca sectiunea e si writeable = PE Header writeable intentionat
            // A doua metoda de a face header-ul writeable fara low-alignment mode
            // Folosit pentru a modifica header-ul la runtime si a ascunde informatii
            if (charact & IMAGE_SCN_MEM_WRITE) {
                r->totalScore += 50;
            }
        }
        
    }

    // --- G. EP Outside Sections ---

    if (!epFound && ep != 0) {
        r->flags |= ANOMALY_EP_OUTSIDE;
        //scor foarte mare, deoarece un EP care nu cade în nicio secțiune e un indiciu foarte puternic de cod generat dinamic (ex: shellcode injectat în memorie sau secțiune creată dinamic de un packer)
    }

    // --- H. Numar sectiuni executabile ---
    // Mai mult de 3 sectiuni executabile e foarte neobisnuit pentru cod legitim
    // Packerii si virusii de fisiere adauga adesea sectiuni executabile extra
    // Evaluat dupa bucla deoarece avem nevoie de numarul total
    if (execSections > 3) {
        r->flags |= ANOMALY_MULTI_EXEC;
    }

    // --- M. Sectiune citibila ---
    if (readableSections == 0) {
    // Un PE fara nicio sectiune citibila e o malformatie foarte clara
    r->totalScore += 50;
    }
}

static void check_overlay(unsigned char* pFile, IMAGE_DOS_HEADER* dos, IMAGE_NT_HEADERS* nt, ScanReport* r, int32 fileSize) {
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    int32 numSections = nt->FileHeader.NumberOfSections;
    int32 ep = nt->OptionalHeader.AddressOfEntryPoint;

    int32 lastSectionEnd = 0;
    for (int i = 0; i < numSections; i++) {
        int32 end = sec[i].PointerToRawData + sec[i].SizeOfRawData;
        if (end > lastSectionEnd) lastSectionEnd = end;
    }

    // Guard — fara sectiuni nu putem determina overlay-ul corect
    if (lastSectionEnd == 0) return;

    // --- 1. NT Headers in overlay ---
    if (dos->e_lfanew >= lastSectionEnd)
        r->totalScore += 60;

    // --- 2. Section Table in overlay ---
    int32 sectionTableOffset = dos->e_lfanew
        + sizeof(DWORD)
        + sizeof(IMAGE_FILE_HEADER)
        + nt->FileHeader.SizeOfOptionalHeader;

    if (sectionTableOffset >= lastSectionEnd)
        r->totalScore += 60;

    int32 overlaySize = fileSize - lastSectionEnd;
    if (overlaySize <= 512) return;

    unsigned char* ov = pFile + lastSectionEnd;

    // --- 3. EP in overlay — cert malware, returnam devreme ---
    if (ep >= lastSectionEnd && ep < fileSize) {
        r->flags |= ANOMALY_EP_IN_OVERLAY;
        r->totalScore += 90;
        return;
    }

    // --- 4. PE embedded — cert malware, returnam devreme ---
    if (overlaySize > 64) {
        IMAGE_DOS_HEADER* overlayDos = (IMAGE_DOS_HEADER*)ov;
        if (overlayDos->e_magic == IMAGE_DOS_SIGNATURE) {
            r->flags |= ANOMALY_EMBEDDED_PE;
            r->totalScore += 90;
            return;
        }
    }

    // --- 5. Multiple PE-uri embedded — scanam doar primii 4096 bytes ---
    int32 scanLimit;
    if (overlaySize < 4096) {
        scanLimit = overlaySize - 2;
    } else {
        scanLimit = 4096;
    }
    int32 embeddedPECount = 0;
    for (int32 j = 0; j < scanLimit; j++) {
        if (ov[j] == 'M' && ov[j + 1] == 'Z') {
            embeddedPECount++;
            if (embeddedPECount > 1) {
                r->totalScore += 50;
                break;
            }
        }
    }

    // --- 7. Certificat digital fals ---
    if (overlaySize > 4 && ov[0] == 0x30 && ov[1] == 0x82) {
        int32 certRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        if (certRVA == 0)
            r->totalScore += 40;
    }

    // --- 8. NOP sled ---
    if (overlaySize > 16) {
        int32 nopCount = 0;
        for (int32 j = 0; j < 16; j++)
            if (ov[j] == 0x90) nopCount++;
        if (nopCount > 8) {
            r->flags |= ANOMALY_NOP_SLED;
            r->totalScore += 60;
        }
    }

    // --- 9. Overlay mai mare decat sectiunile combinate ---
    if (overlaySize > lastSectionEnd)
        r->totalScore += 40;

    // --- 10. Entropie — cel mai costisitor, ultimul ---
    // Samplem doar primii 65536 bytes pentru eficienta
    int32 sampleSize;
    if (overlaySize > 65536) {
        sampleSize = 65536;
    } else {
        sampleSize = overlaySize;
    }
    double h = calculate_entropy(ov, sampleSize);
    if (h > 7.2) {
        r->flags |= ANOMALY_ENTR_OVERLAY;
        r->totalScore += 60;
    } else {
        r->totalScore += 15;
    }
}

// Verifică prezența TLS Callbacks
// static int32 check_tls_presence(IMAGE_NT_HEADERS* nt, int32 currentResult) {
//     if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0) {
//         if (currentResult == 666) return 674; // RWE + TLS = High Suspicion
//         return currentResult; // Just TLS present
//     }
//     return currentResult;
// }

int32 scanfile(Database *db, Workqueue *wq, int32 indexq, int8 *thread_buffer) {
    AcquireSRWLockShared(&db->lock);
    int8 *dirpath = db->pool + db->entries[indexq].diroffset;
    int8 *filename = db->pool + db->entries[indexq].fileoffset;
    
    joinpath(dirpath, filename, thread_buffer);
    ReleaseSRWLockShared(&db->lock);

    ScanReport fileReport = { ANOMALY_NONE, 0, 0.0 };

    HANDLE hFile = CreateFileA((char*)thread_buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) { 
        return 1; 
    }

    LARGE_INTEGER size;
    GetFileSizeEx(hFile, &size);
    int32 finalResult = 10;

    // --- Mapping ---
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap) {
        unsigned char* pFile = (unsigned char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (pFile) {
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pFile;

            // --- Analiză PE ---
            if (size.QuadPart >= 64 && dos->e_magic == IMAGE_DOS_SIGNATURE) {
                int32 ntOff = (int32)dos->e_lfanew;

                if (ntOff + sizeof(IMAGE_NT_HEADERS) <= (int32)size.QuadPart) {
                    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pFile + ntOff);
                    
                    if (nt->Signature == IMAGE_NT_SIGNATURE) {
                        finalResult = 5; // Valid PE

                        // 1. Verificăm malformații de Header
                        check_header_malformations(pFile, nt, &fileReport);

                        // 2. Verificăm Secțiunile
                        IMAGE_SECTION_HEADER* secTable = IMAGE_FIRST_SECTION(nt);
                        int numSec = nt->FileHeader.NumberOfSections;

                        if ((unsigned char*)(secTable + numSec) <= (pFile + size.QuadPart)) {
                            check_section_anomalies(pFile, nt, &fileReport, (int32)size.QuadPart);

                            if ((fileReport.flags & ANOMALY_SEC_IN_HEADER) && (nt->OptionalHeader.FileAlignment == nt->OptionalHeader.SectionAlignment && nt->OptionalHeader.FileAlignment <= 0x200)) {
                                fileReport.totalScore += 40;
                            }

                            if (fileReport.totalScore > 50) {
                                check_trailing_dots_imports(pFile, nt, &fileReport, (int32)size.QuadPart);
                            }
                            // 3. Verificăm TLS (folosind rezultatul de la secțiuni pentru context)
                            //finalResult = check_tls_presence(nt, finalResult);
                        } else {
                            finalResult = 668; // Out of bounds
                        }
                    }
                } else {
                    finalResult = 6; // Doar MZ
                }
            }
            UnmapViewOfFile(pFile);
        }
        CloseHandle(hMap);
    }

    CloseHandle(hFile);
    return finalResult;
}
