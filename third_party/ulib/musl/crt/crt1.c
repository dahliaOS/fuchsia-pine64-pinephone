#include <features.h>

#include <runtime/compiler.h>

int main(int, char**, void*);
__NO_RETURN int __libc_start_main(int (*)(int, char**, void*), void* arg);

__SECTION(".crt")
void _start(void* arg) {
    __libc_start_main(main, arg);
}
