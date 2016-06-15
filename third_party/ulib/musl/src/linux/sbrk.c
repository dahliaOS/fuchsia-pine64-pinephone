#include "syscall.h"
#include <errno.h>
#include <stdint.h>

void* sbrk(intptr_t inc) {
    if (inc) return (void*)__syscall_ret(-ENOMEM);
    return (void*)__syscall(SYS_brk, 0);
}
