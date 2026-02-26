#include "workqueue.h"

Workqueue *mkqueue() {
    Workqueue *wq = (Workqueue *)malloc(sizeof(Workqueue));
    assert(wq);
    wq->items = $4 malloc($i Workqueuesize * sizeof(int32));
    assert(wq->items);
    wq->h = 0;
    wq->t = 0;
    wq->num = 0;
    wq->cap = Workqueuesize;
    InitializeSRWLock(&wq->lock);
    InitializeConditionVariable(&wq->not_empty);
    InitializeConditionVariable(&wq->not_full);

    return wq;
}

void pushqueue(Workqueue *wq, int32 index) {
    AcquireSRWLockExclusive(&wq->lock); 
    while (wq->num == wq->cap) {
        SleepConditionVariableSRW(&wq->not_full, &wq->lock, INFINITE, 0); // Folosim wq->not_full pe post de wake condition, wq->lock se deschide pentru a permite altor threaduri sa curete coada
    }
    wq->items[wq->t] = index;  // Folosim index deoarece daca am folosi pointer-ul, Entry-urile pot fi mutate in memorie in timpul resize-ului bazei de date si astfel accesezi o zona de memorie invalida
    wq->t = (wq->t + 1) % wq->cap;
    wq->num++;
    WakeConditionVariable(&wq->not_empty); 
    ReleaseSRWLockExclusive(&wq->lock);
}

int32 popqueue(Workqueue *wq) {
    AcquireSRWLockExclusive(&wq->lock); 
    while (wq->num == 0) {
        SleepConditionVariableSRW(&wq->not_empty, &wq->lock, INFINITE, 0);
    }
    int32 index = wq->items[wq->h];
    wq->h = (wq->h + 1) % wq->cap;
    wq->num--;
    WakeConditionVariable(&wq->not_full); 
    ReleaseSRWLockExclusive(&wq->lock);
    
    return index;
}

void showqueue(Workqueue *wq) {
    AcquireSRWLockShared(&wq->lock); 

    if (!wq || wq->num == 0) {
        printf("Queue is empty.\n");
        ReleaseSRWLockShared(&wq->lock);
        return;
    }

    printf("--- Queue Contents (%d items) ---\n", wq->num);
    int32 index = wq->h;
    for (int32 i = 0; i < wq->num; i++) {
        printf("[%d] Index: %d\n", i, wq->items[index]);
        index = (index + 1) % wq->cap;
    }
    printf("--- End of Queue ---\n");
    ReleaseSRWLockShared(&wq->lock);
}

void destroyqueue(Workqueue *wq) {
    if (!wq) return;

    if (wq->items) 
        free(wq->items);

    free(wq);
}