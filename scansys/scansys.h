#include "../antiviRus/antiviRus.h"
#include "../database/database.h"
#include "../workqueue/workqueue.h"

struct worker{
    Database *db;
    Workqueue *iterQueue;
    Workqueue *scanQueue;
    volatile long active_tasks; 
};

typedef struct worker ThreadWorker;

DWORD WINAPI IteratorWorker(LPVOID);
DWORD WINAPI ScannerWorker(LPVOID);
void startsys(Database *);
