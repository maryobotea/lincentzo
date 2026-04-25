#include "../antiviRus/antiviRus.h"

struct s_entry {
    int32 fileoffset;
    int32 diroffset;
    bool deleted;
};

typedef struct s_entry Entry;

struct s_hashnode {
    int32 next;
};

typedef struct s_hashnode HashNode;

struct s_database {
    Entry *entries;
    HashNode *nodes;
    int32 *hashindexes;

    int32 *folderhashes;   // Aici avem offseturile folderelor in functie de hashuri
    int32 foldercap;   // Capacitatea folderhashes
    int32 foldernum;  // Numarul de foldere unice

    int32 *filehashes;   // Aici avem offseturile fisierelor in functie de hashuri
    int32 filecap;   // Capacitatea filehashes
    int32 filenum;  // Numarul de fisiere unice

    int8 *pool;         // Rezervorul de memorie (String Pool) pentru nume
    int32 poolcap;    // Capacitatea pool-ului
    int32 poolused;   // Cat din pool am folosit deja

    int32 cap;          // Capacitatea curenta (numar de entries)
    int32 num;          // Numarul actual de fisiere salvate
    int32 hashsize;

    SRWLOCK lock;
};

typedef struct s_database Database;

int32 hash(int8 *, int8 *, int8);

int32 hashpath(int8 *, int8);

Database *mkdatabase();

void addtodb(Database *, int8 *, int8 *);

void findbypathdb(Database *, int8 *);

void lazypopfromdb(Database *, int8 *);

void showdb(Database *);

void destroydb(Database *);

typedef struct s_database Database;
