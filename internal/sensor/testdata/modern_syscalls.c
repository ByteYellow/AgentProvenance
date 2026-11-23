#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *replace_from_worker(void *unused) {
    int fd = open("/proc/self/exe", O_PATH | O_CLOEXEC);
    char *av[] = {"fd-exec-fixture", "finished", NULL};
    syscall(SYS_execveat, fd, "", av, environ, AT_EMPTY_PATH);
    _exit(8);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "finished")) return 0;
    if (argc != 2) return 1;
    struct sockaddr_in6 dst = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT,
                               .sin6_port = htons(atoi(argv[1]))};
    int sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (sock < 0 || connect(sock, (void *)&dst, sizeof(dst))) return 2;
    close(sock);
    int dir = open(".", O_PATH | O_DIRECTORY);
    struct open_how how = {.flags = O_CREAT | O_RDWR, .mode = 0600, .resolve = RESOLVE_BENEATH};
    int file = syscall(SYS_openat2, dir, ".env-fixture", &how, sizeof(how));
    if (file < 0) return 3;
    close(file);
    how.flags = O_RDONLY;
    how.mode = 0;
    file = syscall(SYS_openat2, dir, ".env-fixture", &how, sizeof(how));
    if (file < 0) return 4;
    close(file);
    if (syscall(SYS_openat2, dir, ".env-missing", &how, sizeof(how)) != -1 || errno != ENOENT) return 5;
    if (syscall(SYS_execveat, -1, "", argv, environ, AT_EMPTY_PATH) != -1 || errno != EBADF) return 6;
    pthread_t t;
    if (pthread_create(&t, NULL, replace_from_worker, NULL)) return 7;
    pthread_join(t, NULL);
    return 9;
}
