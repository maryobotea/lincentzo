#include "utils.h"

#include "utils.h"

void joinpath(int8 *dir, int8 *file, int8 *dest) {
    int lendir = strlen((char*)dir);
    int lenfile = strlen((char*)file);

    // Cazul 1: Daca nu avem director, copiem direct doar fisierul
    if (lendir == 0) {
        memcpy(dest, file, lenfile + 1); // +1 pentru a copia si '\0'
        return;
    }

    // Cazul 2: Daca nu avem fisier, copiem direct doar directorul
    if (lenfile == 0) {
        memcpy(dest, dir, lendir + 1);
        return;
    }

    // Cazul 3: Normal. Verificam intai daca directorul se termina deja in '\' (ex: "C:\")
    memcpy(dest, dir, lendir);
    
    if (dir[lendir - 1] == '\\') {
        // Daca are deja '\', lipim fisierul direct
        memcpy(dest + lendir, file, lenfile + 1);
    } else {
        // Daca nu are '\', il adaugam noi, apoi lipim fisierul
        dest[lendir] = '\\';
        memcpy(dest + lendir + 1, file, lenfile + 1);
    }
}