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
    
    // Aceste fisiere exista 100% pe orice Windows
    int8 *target1 = (int8 *)"C:\\Windows\\explorer.exe";
    int8 *target2 = (int8 *)"C:\\Windows\\System32\\cmd.exe";
    int8 *target3 = (int8 *)"C:\\Windows\\System32\\notepad.exe";
    // Un fisier care nu exista
    int8 *target_fake = (int8 *)"C:\\Windows\\System32\\fisier_fals_12345.exe";

    printf("\n-> Cautam: %s\n", (char*)target1);
    findbypathdb(db, target1);

    printf("\n-> Cautam: %s\n", (char*)target2);
    findbypathdb(db, target2);

    printf("\n-> Cautam: %s\n", (char*)target3);
    findbypathdb(db, target3);

    printf("\n-> Cautam FALS: %s\n", (char*)target_fake);
    findbypathdb(db, target_fake);

    // 3. TESTAM STERGEREA (Lazy Pop)
    printf("\n[*] TEST STERGERE: Eliminam cmd.exe din baza de date...\n");
    lazypopfromdb(db, target2);
    
    printf("-> Cautam din nou: %s\n", (char*)target2);
    findbypathdb(db, target2); // Acum ar trebui sa zica "Not Found"


    printf("\n[*] Eliberare memorie...\n");
    destroydb(db);

    printf("\nProgram incheiat. Apasa ENTER pentru iesire...");
    getchar();

    return 0;
}