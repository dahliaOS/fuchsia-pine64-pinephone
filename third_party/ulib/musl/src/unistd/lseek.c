#include "libc.h"
#include "syscall.h"
#include <unistd.h>

off_t lseek(int fd, off_t offset, int whence) {
#ifdef SYS__llseek
    off_t result;
    return syscall(SYS__llseek, fd, offset >> 32, offset, &result, whence) ? -1 : result;
#else
    return syscall(SYS_lseek, fd, offset, whence);
#endif
}

LFS64(lseek);
