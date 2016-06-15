#include "libc.h"
#include "syscall.h"
#include <errno.h>
#include <unistd.h>

static int io_close(int fd) {
    return 0;
}
weak_alias(io_close, __libc_io_close);

static int dummy(int fd) {
    return fd;
}

weak_alias(dummy, __aio_close);

int close(int fd) {
    fd = __aio_close(fd);
    return __libc_io_close(fd);
}
