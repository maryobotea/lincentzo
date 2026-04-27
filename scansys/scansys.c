#include "scansys.h"
#include "../scanfile/scanfile.h"
#include "../utils/utils.h"

// Thread-ul care se ocupă de iterarea folderelor (Discovery)
DWORD WINAPI IteratorWorker(LPVOID lpParam) {
    ThreadWorker *ctx = (ThreadWorker *)lpParam;
    WIN32_FIND_DATAA fd;
    
    int8 *thread_buffer = $1 malloc(32768);
    int8 *search_buffer = $1 malloc(32768);
    if (!thread_buffer || !search_buffer) return 1;

    while (1) {
        int32 index = popqueue(ctx->iterQueue);
        if (index == -1) break; 

        AcquireSRWLockShared(&ctx->db->lock);
        int8 *dirpath = $1 (ctx->db->pool + ctx->db->entries[index].diroffset);
        int8 *filename = $1 (ctx->db->pool + ctx->db->entries[index].fileoffset);
        joinpath(dirpath, filename, thread_buffer);
        ReleaseSRWLockShared(&ctx->db->lock);

        joinpath(thread_buffer, $1 "*", search_buffer);
        HANDLE hFind = FindFirstFileExA((char*)search_buffer, FindExInfoBasic, &fd, FindExSearchNameMatch, NULL, 0);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

                int32 newIndex = addtodb(ctx->db, thread_buffer, $1 fd.cFileName);
                if (newIndex != -1) {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                            InterlockedIncrement(&ctx->active_tasks);
                            pushqueue(ctx->iterQueue, newIndex);
                        }
                    } else {
                        InterlockedIncrement(&ctx->active_tasks);
                        pushqueue(ctx->scanQueue, newIndex);
                    }
                }
            } while (FindNextFileA(hFind, &fd) != 0);
            FindClose(hFind);
        }
        
        InterlockedDecrement(&ctx->active_tasks);
    }
    
    free(thread_buffer);
    free(search_buffer);
    return 0;
}

// Thread-ul care se ocupă de scanarea propriu-zisă a fișierelor (Analysis)
DWORD WINAPI ScannerWorker(LPVOID lpParam) {
    ThreadWorker *ctx = (ThreadWorker *)lpParam;
    int8 *thread_buffer = (int8 *)malloc(32768);
    if (!thread_buffer) return 1;

    while (1) {
        int32 index = popqueue(ctx->scanQueue);
        if (index == -1) break; 

        // Rulăm motorul euristic din scanfile.c
        // Transmițând thread_buffer, eliminăm malloc-ul din interiorul scanării
        scanfile(ctx->db, ctx->scanQueue, index, thread_buffer);

        InterlockedDecrement(&ctx->active_tasks);
    }
    
    free(thread_buffer);
    return 0;
}


void startsys(Database *db) {
    // 1. Pregatirea infrastructurii (Cozi mari pentru a evita blocajele de I/O)
    Workqueue *iterQueue = mkqueue(); 
    Workqueue *scanQueue = mkqueue();

    ThreadWorker *worker = (ThreadWorker *)malloc(sizeof(ThreadWorker));
    if (!worker) return;

    worker->db = db;
    worker->iterQueue = iterQueue;
    worker->scanQueue = scanQueue;
    worker->active_tasks = 0;

    // 2. Calculam resursele CPU (ex: 20 nuclee -> 15 Scannere, 5 Iteratoare)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int32 numThreads = sysInfo.dwNumberOfProcessors;
    
    int32 numIterators = numThreads / 4; 
    if (numIterators < 1) numIterators = 1;
    int32 numScanners = numThreads - numIterators;

    HANDLE *threads = (HANDLE *)malloc(numThreads * sizeof(HANDLE));
    assert(threads);

    printf("[i] Configurare dinamica: %d Scannere si %d Iteratoare.\n", numScanners, numIterators);

    // 3. Pornim Scannerele (Consumatorii)
    for (int i = 0; i < numScanners; i++) {
        threads[i] = CreateThread(NULL, 0, ScannerWorker, worker, 0, NULL);
    }

    // 4. Pornim Iteratoarele (Producatorii)
    for (int i = numScanners; i < numThreads; i++) {
        threads[i] = CreateThread(NULL, 0, IteratorWorker, worker, 0, NULL);
    }

    // 5. DETECTARE DISK-URI (Varianta eficienta propusa de tine)
    char driveBuffer[256];
    DWORD length = GetLogicalDriveStringsA(sizeof(driveBuffer), driveBuffer);

    if (length > 0 && length < sizeof(driveBuffer)) {
        char *currentDrive = driveBuffer;
        while (*currentDrive) {
            UINT driveType = GetDriveTypeA(currentDrive);
            
            // Scanăm doar unități fixe (SSD/HDD) sau stick-uri USB
            if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
                printf("[i] Detectat disk: %s - Se adauga la scanare...\n", currentDrive);
                
                // Adăugăm rădăcina în baza de date
                int32 driveIndex = addtodb(db, (int8*)"", (int8*)currentDrive);
                if (driveIndex != -1) {
                    // Marcam task-ul inainte de push ca sa nu avem race conditions
                    InterlockedIncrement(&worker->active_tasks);
                    pushqueue(iterQueue, driveIndex);
                }
            }
            // Trecem la următorul string din buffer (formatul este X:\0Y:\0\0)
            currentDrive += strlen(currentDrive) + 1;
        }
    }

    // 6. MONITORIZARE SI ASTEPTARE
    // Lăsăm un mic delay să se populeze cozile
    Sleep(200); 

    while (1) {
        long pending = InterlockedAdd(&worker->active_tasks, 0);
        
        // Afișăm progresul pe o singură linie care se updatează
        printf("\r[*] Analiza in curs... Task-uri active: %-8ld | Elemente DB: %-8d", pending, db->num);
        fflush(stdout);

        if (pending <= 0) {
            // Re-verificăm după o scurtă pauză pentru a fi siguri că nu e doar latență de disc
            Sleep(300);
            if (InterlockedAdd(&worker->active_tasks, 0) <= 0) break;
        }
        Sleep(200);
    }

    // 7. SEMNALIZARE OPRIRE (Trimitere -1 pentru a elibera thread-urile din popqueue)
    for (int i = 0; i < numThreads; i++) {
        pushqueue(iterQueue, -1);
        pushqueue(scanQueue, -1);
    }

    // Așteptăm sincronizarea finală a tuturor firelor de execuție
    WaitForMultipleObjects(numThreads, threads, TRUE, INFINITE);
    
    printf("\n\n[+] Scanare finalizata cu succes pe toate unitatile.\n");

    // 8. CURATENIE
    for (int i = 0; i < numThreads; i++) {
        CloseHandle(threads[i]);
    }
    free(threads);
    destroyqueue(iterQueue);
    destroyqueue(scanQueue);
    free(worker);
}
