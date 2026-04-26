#include "antiviRus.h"
#include "../database/database.h"
#include "../workqueue/workqueue.h"
#include "../scanfile/scanfile.h"
#include "../scansys/scansys.h"
#include "../utils/utils.h"

int main(int argc, char *argv[]) {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    printf("================================================\n");
    printf("   ANTIVIRUS ENGINE - TESTARE MULTITHREADING    \n");
    printf("================================================\n\n");

    // 1. Creăm baza de date (String Pool + Hash Table)
    printf("[*] Initializare baza de date...\n");
    Database *db = mkdatabase();
    if (!db) {
        printf("[!] Eroare: Nu s-a putut aloca memoria pentru baza de date.\n");
        return 1;
    }

    // 2. Pornim motorul de scanare!
    // startsys va prelua controlul, va porni thread-urile, va detecta 
    // disk-urile si va afisa telemetria pe ecran datorita printf-urilor adaugate.
    startsys(db);

    printf("\n================================================\n");
    printf("[+] MAPARE FINALIZATA CU SUCCES!\n");
    printf("[*] Total elemente (fisiere/foldere) gasite: %d\n", db->num);
    printf("================================================\n");

    // Afisam DOAR primele 20 ca sa ne demonstram ca e corect
    printf("Primele 20 de elemente gasite:\n");
    AcquireSRWLockShared(&db->lock);
    for (int i = 0; i < 20 && i < db->num; i++) {
        if (!db->entries[i].deleted) {
            int8 *d = $1 (db->pool + db->entries[i].diroffset);
            int8 *f = $1 (db->pool + db->entries[i].fileoffset);
            printf("[%d] %s\\%s\n", i, d, f);
        }
    }
    ReleaseSRWLockShared(&db->lock);

    // 4. Curatenie (prevenim memory leaks)
    printf("\n[*] Eliberare memorie...\n");
    destroydb(db);

    // 5. Pauza ca sa poti analiza output-ul inainte sa se inchida consola
    printf("\nProgram incheiat cu succes. Apasa ENTER pentru iesire...");

    return 0;
}