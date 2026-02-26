#include "scanfile.h"
#include "../antiviRus/antiviRus.h"

void scanfile(Database *db, Workqueue *wq, int32 indexq) {
    AcquireSRWLockShared(&db->lock);
    int8 *dir = db->pool + db->entries[indexq].diroffset;
    int8 *file = db->pool + db->entries[indexq].fileoffset;
    ReleaseSRWLockShared(&db->lock);

    int8 *fullpath = joinpath(dir, file);
    DWORD attr = GetFileAttributesA(fullpath);
    free(fullpath);

    if (attr == INVALID_FILE_ATTRIBUTES) return;
}