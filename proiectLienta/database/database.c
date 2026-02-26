#include "database.h"

int32 hash(int8 *dir, int8 *file, int8 capacity) {
    int32 h = 5381, c;

    while ((c = *dir++)) {
        h = ((h << 5) + h) + c;
    }

    h = ((h << 5) + h) + '\\';

    while ((c = *file++)) {
        h = ((h << 5) + h) + c;
    }
    
    return h % capacity;
}

int32 hashpath(int8 *path, int8 capacity) {
    int32 h = 5381, c;

    while ((c = *path++)) {
        h = ((h << 5) + h) + c;
    }

    return h % capacity;
}

Database *mkdatabase() {
    Database *db = (Database *)malloc(sizeof(Database));
    assert(db);   

    db->cap = Blocksize;              // Număr maxim de fișiere inițial
    db->hashsize = Hashsize;       // Dimensiune tabelă hash (număr prim)
    db->poolcap = 1 * 1000 * 1000;   
    db->num = 0;
    db->poolused = 0;
    db->foldercap = Folderhashsize;
    db->foldernum = 0;
    db->filecap = Filehashsize;
    db->filenum = 0;

    db->entries = (Entry *)malloc(db->cap * sizeof(Entry));
    assert(db->entries);   

    db->nodes = (HashNode *)malloc(db->cap * sizeof(HashNode));
    assert(db->nodes);     

    db->hashindexes = $4 malloc(db->hashsize * sizeof(int32));
    assert(db->hashindexes);   

    db->folderhashes = $4 malloc(db->foldercap * sizeof(int32));
    assert(db->folderhashes);   

    db->filehashes = $4 malloc(db->filecap * sizeof(int32));
    assert(db->filehashes);   

    db->pool = $1 malloc(db->poolcap);
    assert(db->pool);   

    if (!db->entries || !db->nodes || !db->hashindexes || !db->pool || !db->folderhashes || !db->filehashes) {
        destroydb(db);
        return NULL;
    }

    memset(db->hashindexes, -1, db->hashsize * sizeof(int32));
    memset(db->folderhashes, -1, db->foldercap * sizeof(int32));
    memset(db->filehashes, -1, db->filecap * sizeof(int32));

    InitializeSRWLock(&db->lock);

    return db;
}

void addtodb(Database *db, int8 *dir, int8 *file) {
    AcquireSRWLockExclusive(&db->lock);
    if (db->num >= db->cap) {
        db->cap *= 2; 
        
        db->entries = (Entry *)realloc(db->entries, db->cap * sizeof(Entry));
        assert(db->entries);   
        
        db->nodes = (HashNode *)realloc(db->nodes, db->cap * sizeof(HashNode));
        assert(db->nodes);    
    }

    if (db->num >= db->hashsize * 0.75) 
        hashresize(db);

    int32 h = hash(dir, file, db->hashsize);

    int32 i = db->num;
    db->entries[i].diroffset = adddirpool(db, dir);   
    db->entries[i].fileoffset = addfilepool(db, file);

    db->nodes[i].next = db->hashindexes[h];
    db->hashindexes[h] = i;
    db->num++;

    ReleaseSRWLockExclusive(&db->lock);
}

int32 adddirpool(Database *db, int8 *dir) {
    int32 len = strlen($c dir) + 1;

    if (db->foldernum >= db->foldercap * 0.75) {
        dirhashresize(db);
    }

    int32 h = hashpath(dir, db->foldercap);
    int32 start_h = h;

    while (db->folderhashes[h] != -1) {
        int8 *existingdir = $1 (db->pool + db->folderhashes[h]);
        if (strcmp($c dir, $c existingdir) == 0) 
            return db->folderhashes[h]; 
        
        h = (h + 1) % db->foldercap;
        if (h == start_h) break;
    }

    while (db->poolused + len > db->poolcap) {
        db->poolcap *= 2;
        db->pool = $1 realloc(db->pool, db->poolcap);
        assert(db->pool);
    }
 
    int32 offset = db->poolused;
    memcpy(db->pool + offset, dir, len);
    db->poolused += len;
    db->folderhashes[h] = offset;
    db->foldernum++;

    return offset;
}

int32 addfilepool(Database *db, int8 *file) {
    int32 len = strlen($c file) + 1;

    if (db->filenum >= db->filecap * 0.75) {
        filehashresize(db);
    }

    int32 h = hashpath(file, db->filecap);
    int32 start_h = h;

    while (db->filehashes[h] != -1) {
        int8 *existingfile = $1 (db->pool + db->filehashes[h]);
        if (strcmp($c file, $c existingfile) == 0) 
            return db->filehashes[h]; 
        
        h = (h + 1) % db->filecap;
        if (h == start_h) break;
    }

    while (db->poolused + len > db->poolcap) {
        db->poolcap *= 2;
        db->pool = $1 realloc(db->pool, db->poolcap);
        assert(db->pool);
    }

    int32 offset = db->poolused;
    memcpy(db->pool + offset, file, len);
    db->poolused += len;
    db->filehashes[h] = offset; 
    db->filenum++;

    return offset;
}

void dirhashresize(Database *db) {
    int32 oldcap = db->foldercap;
    db->foldercap *= 2;
    int32 *newfolderhashes = $4 malloc(db->foldercap * sizeof(int32));
    assert(newfolderhashes);

    memset(newfolderhashes, -1, db->foldercap * sizeof(int32));

    for (int32 i = 0; i < oldcap; i++) {
        int32 offset = db->folderhashes[i];
        if (offset == -1) continue;
        else {
            int8 *dir = $1 (db->pool + offset);
            int32 h = hashpath(dir, db->foldercap);
            while (newfolderhashes[h] != -1) 
                h = (h + 1) % db->foldercap;
            newfolderhashes[h] = offset;
        }
    }

    free(db->folderhashes);
    db->folderhashes = newfolderhashes;
}

void filehashresize(Database *db) {
    int32 oldcap = db->filecap;
    db->filecap *= 2;
    int32 *newfilehashes = $4 malloc(db->filecap * sizeof(int32));
    assert(newfilehashes);

    memset(newfilehashes, -1, db->filecap * sizeof(int32));

    for (int32 i = 0; i < oldcap; i++) {
        int32 offset = db->filehashes[i];
        if (offset == -1) continue;
        else {
            int8 *file = $1 (db->pool + offset);
            int32 h = hashpath(file, db->filecap);
            while (newfilehashes[h] != -1) 
                h = (h + 1) % db->filecap;
            newfilehashes[h] = offset;
        }
    }

    free(db->filehashes);
    db->filehashes = newfilehashes;
}

void hashresize(Database *db) {
    db->hashsize *= 2;
    int32 *newindexes = $4 malloc(db->hashsize * sizeof(int32));
    assert(newindexes);

    for (int32 i = 0; i < db->hashsize; i++) {
        newindexes[i] = -1;
    }

    for (int32 i = 0; i < db->num; i++) {
        int8 *dir = $1 (db->pool + db->entries[i].diroffset);
        int8 *file = $1 (db->pool + db->entries[i].fileoffset);
        int32 h = hash(dir, file, db->hashsize);
        db->nodes[i].next = newindexes[h];
        newindexes[h] = i;
    }

    free(db->hashindexes);
    db->hashindexes = newindexes;
}

void findbypathdb(Database *db, int8 *path) {
    AcquireSRWLockShared(&db->lock);

    int32 h = hashpath(path, db->hashsize);
    int32 i = db->hashindexes[h];
    bool found = false;
    while (i != -1) {
        Entry *e = &db->entries[i];
        if (e->deleted) {
            i = db->nodes[i].next;
            continue;
        }
        int8 *dirpath = $1 (db->pool + e->diroffset);
        int8 *filename = $1 (db->pool + e->fileoffset);

        int8 *fullpath;
        fullpath = joinpath($1 dirpath, $1 filename);

        if (fullpath) {
            if (strcmp($1 fullpath, $1 path) == 0) {
                printf("Found at index %d: %s\\%s\n", i, dirpath, filename);
                found = true;
                free(fullpath);
                break;
            }
            free(fullpath);
        }
        i = db->nodes[i].next;
    }

    if (!found) {
        printf("Not Found: %s\n", path);
    }
    ReleaseSRWLockShared(&db->lock);
}

void lazypopfromdb(Database *db, int8 *path) {
    AcquireSRWLockExclusive(&db->lock);

    int32 h = hashpath(path, db->hashsize);
    int32 i = db->hashindexes[h];
    int32 prev = -1;

    while (i != -1) {
        Entry *e = &db->entries[i];
        if (!e->deleted) {
            int8 *dirpath = $1 (db->pool + e->diroffset);
            int8 *filename = $1 (db->pool + e->fileoffset);

            int8 *fullpath;
            fullpath = joinpath($1 dirpath, $1 filename);
    
            if (fullpath && strcmp($1 fullpath, $1 path) == 0) {
                if (prev == -1) 
                    db->hashindexes[h] = db->nodes[i].next;
                else 
                    db->nodes[prev].next = db->nodes[i].next;

                e->deleted = true;
                db->num--;  
                free(fullpath);
                break;
            }
            
            if(fullpath) free(fullpath);
        }
        prev = i;
        i = db->nodes[i].next;
    }
    ReleaseSRWLockExclusive(&db->lock);
}

void showdb(Database *db) {
    AcquireSRWLockShared(&db->lock);
    if (!db || db->num == 0) {
        printf("Empty.\n");
        ReleaseSRWLockShared(&db->lock);
        return;
    }

    printf("--- (%d Files) ---\n", db->num);
    
    for (int32 i = 0; i < db->num; i++) {
        Entry *e = &db->entries[i];
        
        if(!e->deleted) {
            int8 *dirpath = $1 (db->pool + e->diroffset);
            int8 *filename = $1 (db->pool + e->fileoffset);

            printf("[%d] %s\\%s (%llu bytes)\n", i, dirpath, filename);
        }
    }
    
    printf("--- End ---\n");
    ReleaseSRWLockShared(&db->lock);
}

void destroydb(Database *db) {
    if (!db) return;

    if (db->entries) 
        free(db->entries);
    
    if (db->nodes) 
        free(db->nodes);

    if (db->hashindexes) 
        free(db->hashindexes);

    if (db->folderhashes) 
        free(db->folderhashes);
    
    if (db->filehashes) 
        free(db->filehashes);

    if (db->pool)
        free(db->pool);

    free(db);
    
}
