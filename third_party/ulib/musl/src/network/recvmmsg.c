#define _GNU_SOURCE
#include "syscall.h"
#include <limits.h>
#include <sys/socket.h>

int recvmmsg(int fd, struct mmsghdr* msgvec, unsigned int vlen, unsigned int flags,
             struct timespec* timeout) {
#if LONG_MAX > INT_MAX
    struct mmsghdr* mh = msgvec;
    unsigned int i;
    for (i = vlen; i; i--, mh++)
        mh->msg_hdr.__pad1 = mh->msg_hdr.__pad2 = 0;
#endif
    return syscall(SYS_recvmmsg, fd, msgvec, vlen, flags, timeout);
}
