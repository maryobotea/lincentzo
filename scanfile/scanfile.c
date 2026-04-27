#include "scanfile.h"
#include "../antiviRus/antiviRus.h" 
#include "../utils/utils.h"

#pragma comment (lib, "wintrust.lib")

#define LN2 0.693147180559945309417

// ========================================================================
// 1. VERIFICARE SEMNATURA DIGITALA (AUTHENTICODE)
// ========================================================================
static int VerifyCertificate(const char* filePath) {
    LONG lStatus;
    WINTRUST_FILE_INFO FileData;
    memset(&FileData, 0, sizeof(FileData));
    FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    
    WCHAR wFilePath[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, filePath, -1, wFilePath, MAX_PATH);
    FileData.pcwszFilePath = wFilePath;
    FileData.hFile = NULL;
    FileData.pgKnownSubject = NULL;

    GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA WinTrustData;
    memset(&WinTrustData, 0, sizeof(WinTrustData));
    WinTrustData.cbStruct = sizeof(WinTrustData);
    WinTrustData.pPolicyCallbackData = NULL;
    WinTrustData.pSIPClientData = NULL;
    WinTrustData.dwUIChoice = WTD_UI_NONE; 
    WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE; 
    WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    WinTrustData.hWVTStateData = NULL;
    WinTrustData.pwszURLReference = NULL;
    WinTrustData.dwUIContext = 0;
    WinTrustData.pFile = &FileData;

    lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
    
    WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

    return (lStatus == ERROR_SUCCESS) ? 1 : 0;
}

// ========================================================================
// HELPERS PENTRU ARHITECTURA PE32 / PE64
// ========================================================================
static inline ULONGLONG GetImageBase(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.ImageBase;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.ImageBase;
}
static inline DWORD GetFileAlignment(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.FileAlignment;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.FileAlignment;
}
static inline DWORD GetSectionAlignment(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SectionAlignment;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SectionAlignment;
}
static inline DWORD GetSizeOfImage(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SizeOfImage;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfImage;
}
static inline DWORD GetSizeOfHeaders(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SizeOfHeaders;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfHeaders;
}
static inline DWORD GetSubsystem(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.Subsystem;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.Subsystem;
}
static inline DWORD GetWin32VersionValue(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.Win32VersionValue;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.Win32VersionValue;
}
static inline DWORD GetNumberOfRvaAndSizes(IMAGE_NT_HEADERS* nt) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.NumberOfRvaAndSizes;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.NumberOfRvaAndSizes;
}
static inline DWORD GetDirRVA(IMAGE_NT_HEADERS* nt, int entry) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.DataDirectory[entry].VirtualAddress;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.DataDirectory[entry].VirtualAddress;
}
static inline DWORD GetDirSize(IMAGE_NT_HEADERS* nt, int entry) {
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return ((IMAGE_NT_HEADERS64*)nt)->OptionalHeader.DataDirectory[entry].Size;
    else return ((IMAGE_NT_HEADERS32*)nt)->OptionalHeader.DataDirectory[entry].Size;
}

// ========================================================================
// UTILS & MATH
// ========================================================================
static inline double fast_log2(double x) {
    if (x <= 0) return 0;
    return log(x) / LN2;
}

double calculate_entropy(int8* data, int32 size) {
    if (size < 256) return 0.0;
    int32 counts[256] = {0};
    int32 total_samples = 0;
    int32 step = (size > 65536) ? (16 * size / 65536) : 1;

    for (int32 i = 0; i < size; i += step) {
        counts[(unsigned char)data[i]]++;
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

// ========================================================================
// HEURISTICI
// ========================================================================

static void check_trailing_dots_imports(unsigned char* pFile, IMAGE_NT_HEADERS* nt, ScanReport* r, int32 fileSize) {
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    int32 numSections = nt->FileHeader.NumberOfSections;
    int32 importRVA = GetDirRVA(nt, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importRVA == 0) return;

    int32 importOffset = rva_to_offset(sec, numSections, importRVA);
    if (importOffset == -1 || importOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return;

    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(pFile + importOffset);
    int32 count = 0;
    while (imp->Name != 0 && count < 256) {
        if ((unsigned char*)imp + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pFile + fileSize) break;
        int32 nameOffset = rva_to_offset(sec, numSections, imp->Name);
        if (nameOffset == -1 || nameOffset >= fileSize) { imp++; count++; continue; }

        int8* dllName = (int8*)(pFile + nameOffset);
        int32 nameLen = 0;
        while (nameLen < 256 && nameOffset + nameLen < fileSize && dllName[nameLen] != 0) nameLen++;

        if (nameLen > 0 && dllName[nameLen - 1] == '.') {
            r->flags |= ANOMALY_TRAILING_DOTS;
            r->totalScore += 40;
            return; 
        }
        imp++; count++;
    }
}

// Verifică malformații în Optional Header - ACUM FARA PUNCTE INVIZIBILE
static void check_header_malformations(unsigned char* pFile, IMAGE_NT_HEADERS* nt, ScanReport* r) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pFile;
    int32 isDLL = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
    
    // 1. Dual PE Header
    int32 minHeaderSize = dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader + nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER); 
    if (GetSizeOfHeaders(nt) < minHeaderSize) {
        r->flags |= ANOMALY_SEC_IN_HEADER;
        r->totalScore += 30;
    }

    // 2. EP pe 0 la un Executabil
    if (nt->OptionalHeader.AddressOfEntryPoint == 0 && !isDLL) {
        r->flags |= ANOMALY_EP_OUTSIDE;
        r->totalScore += 20;
    }

    // 3. Arhitectura Contradictorie
    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        r->flags |= ANOMALY_UNALIGNED_SEC; // Folosim flag-ul de coruptie structurala
        r->totalScore += 30;
    }

    // Restul micilor nereguli (aliniament prost, sizeOfImage gresit) nu le mai penalizam extrem, 
    // decat daca sunt ireale (ex: 0 sectiuni sau peste 96)
    int32 numSections = nt->FileHeader.NumberOfSections;
    if (numSections == 0 || numSections > 96) {
        r->flags |= ANOMALY_UNALIGNED_SEC;
        r->totalScore += 20;
    }
}

// Verifică anomaliile la nivel de secțiune
static void check_section_anomalies(unsigned char* pFile, IMAGE_NT_HEADERS* nt, ScanReport * r, int32 fileSize, int32 isDotNet) {
    int numSections = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    int32 ep = nt->OptionalHeader.AddressOfEntryPoint;
    
    DWORD fAlign = GetFileAlignment(nt);
    DWORD sAlign = GetSectionAlignment(nt);
    DWORD sizeOfHeaders = GetSizeOfHeaders(nt);

    int32 epFound = 0;
    int32 execSections = 0;
    int32 readableSections = 0;

    for (int i = 0; i < numSections; i++) {
        int32 vSize = sec[i].Misc.VirtualSize;
        int32 rSize = sec[i].SizeOfRawData;
        int32 pRaw  = sec[i].PointerToRawData;
        int32 charact = sec[i].Characteristics;

        // IDENTIFICARE COMPORTAMENT LEGITIM (Am sters .xdata sa nu stricam GCC/MinGW)
        if (strncmp((char*)sec[i].Name, "UPX", 3) == 0) r->flags |= FLAG_KNOWN_PACKER;
        if (strncmp((char*)sec[i].Name, ".ndata", 6) == 0) r->flags |= FLAG_KNOWN_INSTALLER;
        if (vSize > 10000000 && rSize > 10000000 && strncmp((char*)sec[i].Name, ".rsrc", 5) == 0) r->flags |= FLAG_KNOWN_INSTALLER; 

        // --- A. RWE ---
        if ((charact & IMAGE_SCN_MEM_EXECUTE) && (charact & IMAGE_SCN_MEM_WRITE)) {
            r->flags |= ANOMALY_RWE;
            r->totalScore += 15;
        }

        // --- B. Nume Suspicios ---
        int32 hasBinaryChars = 0, hasBadNull = 0, foundNull = 0;
        int32 allSame = 1;
        int8 first = sec[i].Name[0];

        for (int32 k = 0; k < 8; k++) {
            int8 c = sec[i].Name[k];
            if (c == 0) { foundNull = 1; continue; }
            if (foundNull) hasBadNull = 1;
            if (c < 32 || c > 126) hasBinaryChars = 1;
            if (c != first) allSame = 0;
        }

        if (hasBinaryChars || hasBadNull) {
            r->flags |= ANOMALY_SUSP_NAME;
            r->totalScore += 15;
        } else if (first == 0 && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            r->flags |= ANOMALY_SUSP_NAME; // Eliminam Punctul invizibil
            r->totalScore += 10;
        }

        // --- C. Hidden Disk Data (RSize > VSize) ---
        // (Am eliminat duplicatul care exista aici in versiunea ta)
        if (rSize > vSize) {
            int32 diff = rSize - vSize;
            if (diff > 8) {
                if (diff > 4096) {
                    r->flags |= ANOMALY_HIDDEN_D_DISC;
                    r->totalScore += 20; // PRAG REDUS PENTRU A SALVA NGEN (.NET)
                } else {
                    int8* caveStart = (int8*)(pFile + pRaw + vSize);
                    for (int32 j = 0; j < diff; j++) {
                        if (caveStart[j] != 0x00 && caveStart[j] != 0x90 && caveStart[j] != 0xCC) {
                            r->flags |= ANOMALY_HIDDEN_D_DISC;
                            r->totalScore += 20;
                            break;
                        }
                    }
                }
            }
        }

        // --- D. EntryPoint in Cave ---
        int32 epInCave;
        if (vSize == 0) {
            epInCave = (ep >= sec[i].VirtualAddress && ep < sec[i].VirtualAddress + rSize);
        } else {
            epInCave = (ep > sec[i].VirtualAddress + vSize && ep < sec[i].VirtualAddress + rSize);
        }

        if (epInCave && !isDotNet) {
            r->flags |= ANOMALY_EP_IN_CAVE;
            r->totalScore += 20; 
        }

        // --- E. Entropie ---
        if (vSize == 0 && (charact & IMAGE_SCN_MEM_EXECUTE)) {
            if (!(r->flags & ANOMALY_EMPTY_SEC)) r->flags |= ANOMALY_EMPTY_SEC;
        }

        if (sec[i].SizeOfRawData == 0 || sec[i].PointerToRawData == 0) {
            if (sec[i].SizeOfRawData == 0 && (charact & IMAGE_SCN_MEM_EXECUTE)) {
                r->flags |= ANOMALY_EMPTY_SEC;
            }
            if (ep >= sec[i].VirtualAddress && ep < sec[i].VirtualAddress + sec[i].Misc.VirtualSize && sec[i].SizeOfRawData == 0 && !isDotNet) {
                r->flags |= ANOMALY_EP_IN_0_SEC;
                r->totalScore += 30;
            }
        } else {
            double h = calculate_entropy((int8*)(pFile + sec[i].PointerToRawData), sec[i].SizeOfRawData);
            if (h > 7.2 && (charact & IMAGE_SCN_MEM_EXECUTE)) {
                r->flags |= ANOMALY_HIGH_ENTROPY;
                r->totalScore += 20;
            } else if (h > 7.8 && !(charact & IMAGE_SCN_MEM_EXECUTE)) {
                r->flags |= ANOMALY_HIGH_ENTROPY;
                if (r->flags & ANOMALY_SUSP_NAME) { r->totalScore += 20; } 
                else { r->totalScore += 10; }
            }
        }

        // --- F. Inflation (VSize > RSize) ---
        if (rSize > 0) {  
            int32 ratio = vSize / rSize;
            if (ratio > 3) {
                if (charact & IMAGE_SCN_MEM_EXECUTE) {
                    r->flags |= ANOMALY_INFLATION;
                    if (ratio > 10) r->totalScore += 30; 
                    else r->totalScore += 10; 
                }
                else if (ratio > 20) {
                    r->flags |= ANOMALY_INFLATION;
                    r->totalScore += 10;
                }
            }
            if ((r->flags & ANOMALY_INFLATION) && (r->flags & ANOMALY_SUSP_NAME)) r->totalScore += 20;
        }

        // --- G. EP Outside Sections ---
        if (ep >= sec[i].VirtualAddress && ep < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            epFound = 1;
        }
        
        // --- H. Numar sectiuni executabile ---
        if (charact & IMAGE_SCN_MEM_EXECUTE) execSections++;

        // --- I. Sectiune dincolo de EOF ---
        if (pRaw != 0 && rSize != 0 && (pRaw + rSize) > fileSize) {
            r->flags |= ANOMALY_SEC_BEYOND_EOF;
        }

        // --- J. & K. Aliniamente gresite ---
        if ((pRaw != 0 && fAlign != 0 && (pRaw % fAlign) != 0) || (sAlign != 0 && (sec[i].VirtualAddress % sAlign) != 0)) {
            r->flags |= ANOMALY_UNALIGNED_SEC;
        }

        // --- L. Sectiuni suprapuse in memoria virtuala ---
        if (i < numSections - 1) {
            int32 currentRawEnd = pRaw + rSize;
            if (currentRawEnd > sec[i+1].PointerToRawData) {
                r->flags |= ANOMALY_SEC_OVERLAP;
                r->totalScore += 5; // Pedeapsa mica pentru GCC/Msys2 care fac asta des
            }
            int32 currentVEnd = sec[i].VirtualAddress + vSize;
            if (currentVEnd > sec[i+1].VirtualAddress) {
                r->flags |= ANOMALY_SEC_OVERLAP;
                r->totalScore += 5;
            }
        }

        // --- M. Sectiune citibila ---
        if (charact & IMAGE_SCN_MEM_READ) readableSections++;

        // --- N. Sectiune in interiorul header-ului PE ---
        if (pRaw != 0 && pRaw < sizeOfHeaders) {
            r->flags |= ANOMALY_SEC_IN_HEADER;
            if (charact & IMAGE_SCN_MEM_WRITE) r->totalScore += 30;
        }
    }

    if (!epFound && ep != 0 && !isDotNet) {
        r->flags |= ANOMALY_EP_OUTSIDE;
        r->totalScore += 20;
    }

    if (execSections > 3) {
        r->flags |= ANOMALY_MULTI_EXEC;
        r->totalScore += 10;
    }

    if (readableSections == 0) {
        r->flags |= ANOMALY_UNALIGNED_SEC; // Punctul invizibil eliminat
        r->totalScore += 20;
    }
}

static void check_overlay(unsigned char* pFile, IMAGE_DOS_HEADER* dos, IMAGE_NT_HEADERS* nt, ScanReport* r, int32 fileSize, int32 isDotNet) {
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    int32 numSections = nt->FileHeader.NumberOfSections;
    int32 ep = nt->OptionalHeader.AddressOfEntryPoint;

    int32 lastSectionEnd = 0;
    for (int i = 0; i < numSections; i++) {
        int32 end = sec[i].PointerToRawData + sec[i].SizeOfRawData;
        if (end > lastSectionEnd) lastSectionEnd = end;
    }

    if (lastSectionEnd == 0) return;

    if (dos->e_lfanew >= lastSectionEnd) {
        r->flags |= ANOMALY_SEC_IN_HEADER;
        r->totalScore += 30;
    }

    int32 sectionTableOffset = dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
    if (sectionTableOffset >= lastSectionEnd) {
        r->flags |= ANOMALY_SEC_IN_HEADER;
        r->totalScore += 30;
    }

    int32 overlaySize = fileSize - lastSectionEnd;
    if (overlaySize <= 512) return;

    unsigned char* ov = pFile + lastSectionEnd;

    // --- 3. EP in overlay ---
    if (ep >= lastSectionEnd && ep < fileSize && !isDotNet) {
        r->flags |= ANOMALY_EP_IN_OVERLAY;
        r->totalScore += 40;
        return;
    }

    // --- 4. PE embedded ---
    if (overlaySize > 64) {
        IMAGE_DOS_HEADER* overlayDos = (IMAGE_DOS_HEADER*)ov;
        if (overlayDos->e_magic == IMAGE_DOS_SIGNATURE) {
            r->flags |= ANOMALY_EMBEDDED_PE;
            r->totalScore += 40; 
            return;
        }
    }

    // --- 5. Multiple PE-uri embedded ---
    int32 scanLimit = (overlaySize < 4096) ? overlaySize - 2 : 4096;
    int32 embeddedPECount = 0;
    for (int32 j = 0; j < scanLimit; j++) {
        if (ov[j] == 'M' && ov[j + 1] == 'Z') {
            embeddedPECount++;
            if (embeddedPECount > 1) {
                r->flags |= ANOMALY_EMBEDDED_PE;
                r->totalScore += 30;
                break;
            }
        }
    }

    // --- 7. Certificat digital fals ---
    if (overlaySize > 4 && ov[0] == 0x30 && ov[1] == 0x82) {
        int32 certRVA = GetDirRVA(nt, IMAGE_DIRECTORY_ENTRY_SECURITY);
        if (certRVA == 0) {
            r->flags |= ANOMALY_ENTR_OVERLAY;
            r->totalScore += 20;
        }
    }

    // --- 8. NOP sled ---
    if (overlaySize > 16) {
        int32 nopCount = 0;
        for (int32 j = 0; j < 16; j++) if (ov[j] == 0x90) nopCount++;
        if (nopCount > 8) {
            r->flags |= ANOMALY_NOP_SLED;
            r->totalScore += 30;
        }
    }

    if (overlaySize > lastSectionEnd) {
        r->flags |= ANOMALY_HIDDEN_D_DISC;
        r->totalScore += 10;
    }

    // --- 10. Entropie ---
    int32 sampleSize = (overlaySize > 65536) ? 65536 : overlaySize;
    double h = calculate_entropy((int8*)ov, sampleSize);
    if (h > 7.2) {
        r->flags |= ANOMALY_ENTR_OVERLAY;
        if (!(r->flags & FLAG_KNOWN_INSTALLER)) r->totalScore += 10;
    }
}

// Funcție care traduce flag-urile binare în explicații "Human-Readable"
static void print_autopsy_report(int32 flags) {
    printf("  [ MOTIVE DETECTIE ]\n");
    if (flags & ANOMALY_RWE) printf("   [-] Memorie RWE: O sectiune are permisiuni Read-Write-Execute simultan (posibil shellcode sau packer).\n");
    if (flags & ANOMALY_SUSP_NAME) printf("   [-] Nume Suspicios: Nume de sectiune care contine caractere binare sau invalide (tehnica de evaziune).\n");
    if (flags & ANOMALY_HIGH_ENTROPY) printf("   [-] Entropie Critica: Date extrem de amestecate. Codul este fie criptat, fie puternic obfuscat.\n");
    if (flags & ANOMALY_INFLATION) printf("   [-] Inflatie de Memorie: Fisierul este mic pe disc, dar cere o cantitate uriasa de memorie RAM (Process Hollowing).\n");
    if (flags & ANOMALY_EP_IN_CAVE) printf("   [-] EntryPoint in Cave: Punctul de pornire este ascuns intr-o zona moarta (Code Cave Injection).\n");
    if (flags & ANOMALY_EMPTY_SEC) printf("   [-] Sectiune Goala: Sectiune executabila fara date pe disc (spatiu rezervat pentru cod generat dinamic).\n");
    if (flags & ANOMALY_EP_IN_0_SEC) printf("   [-] Executie Invizibila: Programul porneste dintr-o sectiune care nu exista fizic pe disc.\n");
    if (flags & ANOMALY_TRAILING_DOTS) printf("   [-] Trailing Dots: Importuri de DLL-uri care se termina in punct (ex: 'kernel32.dll.'). Evaziune loader Windows.\n");
    if (flags & ANOMALY_HIDDEN_D_DISC) printf("   [-] Date Ascunse pe Disc: Date injectate la finalul unei sectiuni, nesemnalate in header-ul virtual.\n");
    if (flags & ANOMALY_SEC_BEYOND_EOF) printf("   [-] Malformatie EOF: O sectiune declara ca are date dincolo de sfarsitul fizic al fisierului.\n");
    if (flags & ANOMALY_UNALIGNED_SEC) printf("   [-] Nealiniere: Sectiuni care incalca regulile de aliniere Windows (incercare de a strica parserele AV).\n");
    if (flags & ANOMALY_SEC_OVERLAP) printf("   [-] Sectiuni Suprapuse: Doua sectiuni se suprapun in memorie (tehnica avansata de ascundere a codului).\n");
    if (flags & ANOMALY_SEC_IN_HEADER) printf("   [-] Dual PE Header / Header Malformat: Date corupte intentionat in antetul fisierului.\n");
    if (flags & ANOMALY_EP_OUTSIDE) printf("   [-] EntryPoint Extern: Punctul de pornire nu apartine niciunei sectiuni valide.\n");
    if (flags & ANOMALY_MULTI_EXEC) printf("   [-] Executabile Multiple: Fisierul are mai mult de 3 sectiuni de cod (specific virusilor de fisiere).\n");
    if (flags & ANOMALY_EP_IN_OVERLAY) printf("   [-] Executie din Overlay: Fisierul ruleaza cod lipit la finalul sau (dupa sectiunile oficiale).\n");
    if (flags & ANOMALY_EMBEDDED_PE) printf("   [-] PE Ascuns (Dropper): A fost gasit un alt executabil intreg atasat in interiorul acestui fisier.\n");
    if (flags & ANOMALY_NOP_SLED) printf("   [-] NOP Sled Detectat: Instructiuni de padding masive la finalul fisierului (specific exploit-urilor).\n");
    if (flags & ANOMALY_ENTR_OVERLAY) printf("   [-] Overlay Criptat: Datele de la finalul fisierului au o entropie foarte mare (Payload criptat).\n");
}

int32 scanfile(Database *db, Workqueue *wq, int32 indexq, int8 *thread_buffer) {
    AcquireSRWLockShared(&db->lock);
    int8 *dirpath = db->pool + db->entries[indexq].diroffset;
    int8 *filename = db->pool + db->entries[indexq].fileoffset;
    joinpath(dirpath, filename, thread_buffer);
    ReleaseSRWLockShared(&db->lock);

    ScanReport fileReport = { ANOMALY_NONE, 0, 0.0 };

    int32 len = strlen((char*)filename);
    if (len < 4) return 0; 
    int8* ext = filename + len - 4;
    
    if (_stricmp((char*)ext, ".exe") != 0 && 
        _stricmp((char*)ext, ".dll") != 0 && 
        _stricmp((char*)ext, ".sys") != 0 &&
        _stricmp((char*)ext, ".exe") != 0 && 
        _stricmp((char*)ext, "_exe") != 0) { 
        return 0; 
    }

    if (VerifyCertificate((char*)thread_buffer) == 1) {
        return 0; // E semnat digital, nu pierdem timpul
    }

    HANDLE hFile = CreateFileA((char*)thread_buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1; 

    LARGE_INTEGER size;
    GetFileSizeEx(hFile, &size);

    if (size.QuadPart >= 64 && size.QuadPart < 100000000) { 
        HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
        if (hMap) {
            unsigned char* pFile = (unsigned char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
            if (pFile) {
                IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pFile;

                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    int32 ntOff = (int32)dos->e_lfanew;

                    if (ntOff > 0 && ntOff + sizeof(IMAGE_NT_HEADERS) <= (int32)size.QuadPart) {
                        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pFile + ntOff);
                        
                        if (nt->Signature == IMAGE_NT_SIGNATURE) {
                            
                            int32 isDotNet = 0;
                            if (GetDirRVA(nt, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR) != 0) {
                                isDotNet = 1;
                            }

                            check_header_malformations(pFile, nt, &fileReport);
                            
                            IMAGE_SECTION_HEADER* secTable = IMAGE_FIRST_SECTION(nt);
                            int numSec = nt->FileHeader.NumberOfSections;

                            if ((unsigned char*)(secTable + numSec) <= (pFile + size.QuadPart)) {
                                check_section_anomalies(pFile, nt, &fileReport, (int32)size.QuadPart, isDotNet);
                                check_trailing_dots_imports(pFile, nt, &fileReport, (int32)size.QuadPart);
                                check_overlay(pFile, dos, nt, &fileReport, (int32)size.QuadPart, isDotNet);
                            }

                            // BEHAVIORAL WHITELISTING & PREVENIRE INTEGER UNDERFLOW
                            if (fileReport.flags & FLAG_KNOWN_INSTALLER) {
                                if (fileReport.totalScore >= 60) fileReport.totalScore -= 60; 
                                else fileReport.totalScore = 0;
                            } 
                            
                            // Aici tratam Packerele (Inainte de coroborare!)
                            if (fileReport.flags & FLAG_KNOWN_PACKER) {
                                // Daca e packer dar ARE header corupt, il consideram malitios!
                                if (fileReport.flags & ANOMALY_SEC_IN_HEADER) {
                                    fileReport.flags &= ~FLAG_KNOWN_PACKER; // Ii anulam scutul!
                                } else {
                                    // Daca e curat, il iertam
                                    if (fileReport.totalScore >= 50) fileReport.totalScore -= 50; 
                                    else fileReport.totalScore = 0;
                                }
                            }

                            // Whitelisting Windows
                            if (strstr((char*)thread_buffer, "C:\\Windows\\") != NULL) {
                                if (fileReport.totalScore >= 80) fileReport.totalScore -= 80;
                                else fileReport.totalScore = 0;
                            }


                            if (fileReport.totalScore >= 30) { 
                                
                                // Daca NU e packer (sau daca a fost packer dar i-am anulat scutul mai sus)
                                if (!(fileReport.flags & FLAG_KNOWN_PACKER)) {
                                    
                                    // Combo 1: Ransomware/Crypter (Entropie + RWE)
                                    if ((fileReport.flags & ANOMALY_HIGH_ENTROPY) && (fileReport.flags & ANOMALY_RWE)) {
                                        fileReport.totalScore += 20; 
                                        if ((fileReport.flags & ANOMALY_EP_IN_CAVE) || (fileReport.flags & ANOMALY_EP_OUTSIDE)) {
                                            fileReport.totalScore += 60; 
                                        }
                                    }

                                    // Combo 2: Injector / Hollowing (Inflatie + RWE + Gol)
                                    if ((fileReport.flags & ANOMALY_INFLATION) && (fileReport.flags & ANOMALY_RWE) && (fileReport.flags & ANOMALY_EMPTY_SEC)) {
                                        fileReport.totalScore += 50; 
                                    }
                                    
                                    // Combo 3: Executie invizibila
                                    if ((fileReport.flags & ANOMALY_EP_IN_0_SEC) && (fileReport.flags & ANOMALY_RWE)) {
                                        fileReport.totalScore += 50;
                                    }
                                }

                                // Restul combo-urilor se aplica oricui (inclusiv packerelor legitime)
                                if (fileReport.flags & ANOMALY_EMBEDDED_PE) {
                                    if (fileReport.flags & ANOMALY_ENTR_OVERLAY) fileReport.totalScore += 20;
                                    if (fileReport.totalScore > 60) fileReport.totalScore += 30; // Dropper nesemnat
                                }

                                if ((fileReport.flags & ANOMALY_SUSP_NAME) && (fileReport.flags & ANOMALY_TRAILING_DOTS)) {
                                    fileReport.totalScore += 60; 
                                }
                            }
                            
                            
                            // 4. ALERTA FINALA
                            if (fileReport.totalScore >= 80) {
                                printf("\n=================================================================\n");
                                printf("[!!!] ALERTA MAXIMA: MALWARE DETECTAT [!!!]\n");
                                printf("=================================================================\n");
                                printf("=> Fisier: %s\n", thread_buffer);
                                printf("=> Nivel Risc: %d/100\n", fileReport.totalScore);
                                printf("=> Semnatura Comportamentala (Flags): 0x%08X\n\n", fileReport.flags);
                                
                                print_autopsy_report(fileReport.flags);
                                
                                printf("=================================================================\n\n");
                                fflush(stdout);
                            }
                        }
                    }
                }
                UnmapViewOfFile(pFile);
            }
            CloseHandle(hMap);
        }
    }
    CloseHandle(hFile);
    
    return fileReport.totalScore; 
}