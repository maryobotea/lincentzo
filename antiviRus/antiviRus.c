#include "antiviRus.h"
#include "../database/database.h"
#include "../workqueue/workqueue.h"
#include "../scanfile/scanfile.h"
#include "../scansys/scansys.h"
#include "../utils/utils.h"

int main(int argc, char *argv[]) {
    // Spunem Windows-ului sa nu ne mai blocheze cu popup-uri ascunse
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);

    printf("================================================\n");
    printf("   TEST SUPREM: INDEXARE C:\\ SI INTEROGARE DB  \n");
    printf("================================================\n\n");

    Database *db = mkdatabase();

    // 1. Pornim explorarea pe C:\ (Foloseste varianta de startsys DOAR cu Iteratoare!)
    startsys(db); 

    printf("\n================================================\n");
    printf("[+] MAPARE FINALIZATA! Baza de date a indexat %d elemente.\n", db->num);
    printf("================================================\n\n");

    // 2. TESTAM CAUTAREA IN BAZA DE DATE (O(1) pe 800.000+ elemente)
    printf("[*] TESTAM HASH-UL: Cautam fisiere critice din Windows...\n");

    printf("\n[*] Eliberare memorie...\n");
    destroydb(db);

    printf("\nProgram incheiat. Apasa ENTER pentru iesire...");
    getchar();

    return 0;
}