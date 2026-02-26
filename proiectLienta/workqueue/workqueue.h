#include "../antiviRus/antiviRus.h"
#include "../database/database.h"

struct s_queue {
    int32 *items;           
    int32 cap; // punem capacity aici pentru a putea sa il incarcam in cache si sa nu trebuiasca sa il luam din define
    int32 h;
    int32 t;
    int32 num;

    SRWLOCK lock;          
    CONDITION_VARIABLE not_empty;
    CONDITION_VARIABLE not_full;
};

typedef struct s_queue Workqueue;

Workqueue *mkqueue();

void pushqueue(Workqueue *, int32);

int32 popqueue(Workqueue *);

void showqueue(Workqueue *);

void destroyqueue(Workqueue *);