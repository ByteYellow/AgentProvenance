#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int restrict_call(int syscall_number, unsigned action) {
#if defined(__aarch64__)
    const unsigned arch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    const unsigned arch = AUDIT_ARCH_X86_64;
#else
#error unsupported architecture
#endif
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {sizeof(code) / sizeof(code[0]), code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, &program);
}

int main(int argc, char **argv) {
    int is_read = argc == 3 && !strcmp(argv[1], "read");
    int is_connect = argc == 4 && !strcmp(argv[1], "connect");
    if (!is_read && !is_connect) return 2;
    int fd = -1;
    struct sockaddr_in address = {.sin_family = AF_INET};
    if (is_connect) {
        if (strcmp(argv[2], "127.0.0.1")) return 2;
        address.sin_port = htons((unsigned short)atoi(argv[3]));
        if (inet_pton(AF_INET, argv[2], &address.sin_addr) != 1) return 2;
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return 3;
    }
    if (restrict_call(is_read ? SYS_openat : SYS_connect,
                      is_read ? SECCOMP_RET_LOG : SECCOMP_RET_ERRNO | EPERM)) {
        perror("install demonstration filter");
        return 4;
    }
    // Leave time for the independent procfs observer to read the active state.
    usleep(1200000);
    errno = 0;
    long result = is_read
        ? syscall(SYS_openat, AT_FDCWD, argv[2], O_RDONLY, 0)
        : syscall(SYS_connect, fd, &address, sizeof(address));
    int saved = errno;
    if (is_read && result >= 0) close((int)result);
    if (fd >= 0) close(fd);
    printf("{\"pid\":%d,\"tid\":%ld,\"operation\":\"%s\",\"result\":%ld,\"errno\":%d}\n",
           getpid(), syscall(SYS_gettid), argv[1], result, saved);
    fflush(stdout);
    usleep(1200000);
    return 0;
}
