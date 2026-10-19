#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int install_filter(unsigned action, unsigned flags) {
#if defined(__aarch64__)
    const unsigned arch = AUDIT_ARCH_AARCH64;
#elif defined(__x86_64__)
    const unsigned arch = AUDIT_ARCH_X86_64;
#else
#error unsupported fixture architecture
#endif
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {sizeof(code) / sizeof(code[0]), code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &filter);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    unsigned action = 0, flags = 0;
    if (!strcmp(argv[1], "plain")) {
        if (setresuid(65534, 65534, 65534)) return 3;
    } else if (!strcmp(argv[1], "log")) {
        action = SECCOMP_RET_LOG;
    } else if (!strcmp(argv[1], "errno") || !strcmp(argv[1], "silent-errno")) {
        action = SECCOMP_RET_ERRNO | EPERM;
        if (!strcmp(argv[1], "errno")) flags = SECCOMP_FILTER_FLAG_LOG;
    } else {
        return 2;
    }
    if (action && install_filter(action, flags)) {
        perror("seccomp fixture");
        return 4;
    }
    printf("{\"pid\":%d,\"tid\":%ld,\"syscall_number\":%d,\"filter_action\":%u,\"filter_flags\":%u}\n",
           getpid(), syscall(SYS_gettid), SYS_openat, action, flags);
    fflush(stdout);
    // The parent reads actual procfs state before allowing the target call.
    char start;
    if (read(STDIN_FILENO, &start, 1) != 1) return 5;
    usleep(30000);
    errno = 0;
    long result = syscall(SYS_openat, AT_FDCWD, argv[2], O_RDONLY, 0);
    int saved = errno;
    if (result >= 0) close((int)result);
    printf("{\"result\":%ld,\"errno\":%d}\n", result, saved);
    fflush(stdout);
    usleep(30000);
    return 0;
}
