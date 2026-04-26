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
        HANDLE hFind = FindFirstFileA($c search_buffer, &fd);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

                int32 newIndex = addtodb(ctx->db, thread_buffer, $1 fd.cFileName);
                
                if (newIndex != -1) {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        
                        // Verificăm dacă este un director normal sau un portal virtual (Junction Point)
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                            // Este director normal, il trimitem la explorat!
                            InterlockedIncrement(&ctx->active_tasks);
                            pushqueue(ctx->iterQueue, newIndex);
                        }
                        // Daca este Reparse Point, a fost adaugat in baza de date,
                        // dar NU il bagam in coada de iterare ca sa evitam buclele si dublurile.
                        
                    } 
                    // Daca aveai fisiere aici, ele raman logica normala
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

// Funcția de management care coordonează tot sistemul
void startsys(Database *db) {
    Workqueue *iterQueue = mkqueue();
    Workqueue *scanQueue = mkqueue(); // Il cream doar ca sa nu dea crash, dar va sta gol

    ThreadWorker *worker = (ThreadWorker *)malloc(sizeof(ThreadWorker));
    assert(worker);
    worker->db = db;
    worker->iterQueue = iterQueue;
    worker->scanQueue = scanQueue;
    worker->active_tasks = 0;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int32 numThreads = sysInfo.dwNumberOfProcessors;
    
    HANDLE *threads = (HANDLE *)malloc(numThreads * sizeof(HANDLE));
    assert(threads);

    printf("[i] Pornire motor de EXPLORARE cu %d thread-uri...\n", numThreads);

    // [!!!] PORNIM DOAR ITERATOARE [!!!]
    for (int i = 0; i < numThreads; i++) {
        threads[i] = CreateThread(NULL, 0, IteratorWorker, worker, 0, NULL);
    }

    // PENTRU TESTARE: In loc de tot C-ul, da-i un folder mic din Windows ca sa vezi daca merge corect si se opreste.
    // Daca ii dai tot C:\ va printa sute de mii de linii.
    int32 driveIndex = addtodb(db, (int8*)"", (int8*)"C:\\");
    
    if (driveIndex != -1) {
        InterlockedIncrement(&worker->active_tasks);
        pushqueue(iterQueue, driveIndex);
    }

    // ASTEPTAM SA TERMINE
    Sleep(100); 
    while (InterlockedAdd(&worker->active_tasks, 0) > 0) {
        Sleep(50); 
    }

    // OPRIM MUNCITORII
    for (int i = 0; i < numThreads; i++) {
        pushqueue(iterQueue, -1);
    }

    WaitForMultipleObjects(numThreads, threads, TRUE, INFINITE);
    printf("\n[+] Gata! Arborele de foldere a fost mapat complet.\n");

    for (int i = 0; i < numThreads; i++) CloseHandle(threads[i]);
    destroyqueue(iterQueue);
    destroyqueue(scanQueue);
    free(threads);
    free(worker);
}