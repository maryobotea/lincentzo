#include "antiviRus.h"
#include "../database/database.h"
#include "../workqueue/workqueue.h"
#include "../scanfile/scanfile.h"
#include "../utils/utils.h"

int main(int argc, char *argv[]) {
    Database *db = mkdatabase();
    Workqueue *wq = mkqueue(); // 4 threaduri de lucru
    
    addtodb(db, (int8 *)"C:\\Users\\Maryo\\Desktop", (int8 *)"Firefox.exe");
    addtodb(db, (int8 *)"C:\\Users\\Maryo\\AppData\\Roaming\\utorrent", (int8 *)"uTorrent.exe");
    addtodb(db, (int8 *)"C:\\Cisco 9.0.0\\Cisco Packet Tracer 9.0.0\\bin", (int8 *)"PacketTracer.exe");
    addtodb(db, (int8 *)"C:\\Users\\Maryo\\Desktop\\MAC", (int8 *)"BON2.pkt");
    
    showdb(db);

    pushqueue(wq, 0);
    pushqueue(wq, 1);
    pushqueue(wq, 2);
    pushqueue(wq, 3);
    
    printf("%d\n", scanfile(db, wq, 1));

    return 0;
}