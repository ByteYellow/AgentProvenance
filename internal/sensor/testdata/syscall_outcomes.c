#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *directory;
static int port, refused_port;
static pthread_barrier_t barrier;

static void report(const char *op, long result) {
    printf("{\"pid\":%d,\"tid\":%ld,\"operation\":\"%s\",\"result\":%ld}\n",
           getpid(), syscall(SYS_gettid), op, result < 0 ? -errno : result);
    fflush(stdout);
}

static void open_pair(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/credentials-%ld", directory, syscall(SYS_gettid));
    long fd = syscall(SYS_openat, AT_FDCWD, path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    report("file_open", fd);
    if (fd >= 0) close(fd);
    snprintf(path, sizeof(path), "%s/missing-credentials-%ld", directory, syscall(SYS_gettid));
    fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
    report("file_open", fd);
    if (fd >= 0) close(fd);
}

static void connect_one(int target, int flags) {
    int fd = socket(AF_INET, SOCK_STREAM | flags, 0);
    if (fd < 0) _exit(2);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(target)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    long result = syscall(SYS_connect, fd, &addr, sizeof(addr));
    report("network_connect", result);
    close(fd);
}

static void *concurrent(void *unused) {
    (void)unused;
    pthread_barrier_wait(&barrier);
    open_pair();
    connect_one(port, 0);
    connect_one(refused_port, 0);
    connect_one(port, SOCK_NONBLOCK);
    return NULL;
}

static void install_filter(unsigned action, unsigned number) {
    // The fixture filters one syscall in its own process, never host policy.
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
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, action),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog filter = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter)) {
        perror("seccomp");
        _exit(3);
    }
}

static void *after_leader(void *arg) {
    usleep(200000);
    if (arg) {
        install_filter(SECCOMP_RET_KILL_PROCESS, SYS_getpid);
        syscall(SYS_getpid);
        _exit(4);
    }
    open_pair();
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    directory = argv[2]; port = atoi(argv[3]); refused_port = atoi(argv[4]);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) return 2;
    if (!strcmp(argv[1], "ordinary-permission")) {
        if (setresuid(65534, 65534, 65534)) return 2;
        open_pair();
        return 0;
    }
    if (!strcmp(argv[1], "seccomp-errno") || !strcmp(argv[1], "seccomp-log")) {
        install_filter(!strcmp(argv[1], "seccomp-errno") ? SECCOMP_RET_ERRNO | EPERM : SECCOMP_RET_LOG, SYS_connect);
        connect_one(port, 0);
        return 0;
    }
    if (!strcmp(argv[1], "concurrent")) {
        pthread_t threads[16];
        pthread_barrier_init(&barrier, NULL, 16);
        for (int i = 0; i < 16; i++) if (pthread_create(&threads[i], NULL, concurrent, NULL)) return 2;
        for (int i = 0; i < 16; i++) pthread_join(threads[i], NULL);
        return 7;
    }
    pthread_t worker;
    int kill = !strcmp(argv[1], "seccomp-kill");
    if (pthread_create(&worker, NULL, after_leader, kill ? (void *)1 : NULL)) return 2;
    // A raw thread exit leaves the other thread running, unlike exit_group.
    syscall(SYS_exit, 7);
    return 4;
}
