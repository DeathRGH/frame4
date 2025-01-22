#include "ptrace.h"

int ptrace(int req, int pid, void *addr, int data) {
    int r;

    errno = NULL;
    r = syscall(26, req, pid, addr, data);

    return r;
}

int wait4(int wpid, int *status, int options, void *rusage) {
    return syscall(7, wpid, status, options, rusage);
}
