#include "utils.h"

int8 *joinpath(int8 *dir, int8 *file) {
    int lendir = strlen(dir);
    int lenfile = strlen(file);
    int8* fullpath = (int8*)malloc((lendir + lenfile + 2)); // +2 pentru '\' si '\0'
    assert(fullpath);
    memcpy(fullpath, dir, lendir);
    fullpath[lendir] = '\\';
    memcpy(fullpath + lendir + 1, file, lenfile);
    fullpath[lendir + lenfile + 1] = '\0';

    return fullpath;
}