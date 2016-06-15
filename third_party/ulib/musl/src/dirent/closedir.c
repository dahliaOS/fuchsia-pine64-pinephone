#include "__dirent.h"
#include "libc.h"
#include <dirent.h>
#include <unistd.h>

int closedir(DIR* dir) {
    int ret = close(dir->fd);
    free(dir);
    return ret;
}
