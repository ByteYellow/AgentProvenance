#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 10000;
    int pause_us = argc > 2 ? atoi(argv[2]) : 0;
    for (int worker = 0; worker < 4; worker++) {
        pid_t pid = fork();
        if (pid < 0) return 2;
        if (pid == 0) {
            char path[128];
            snprintf(path, sizeof(path), "/tmp/agentprov-load-%d", getpid());
            for (int i = 0; i < rounds; i++) {
                int fd = open(path, O_WRONLY | O_CREAT, 0600);
                if (fd < 0) _exit(2);
                close(fd);
                if (pause_us && i % 25 == 24) usleep(pause_us);
            }
            unlink(path);
            _exit(0);
        }
    }
    int rc = 0, status;
    while (wait(&status) > 0) {
        if (status) rc = 1;
    }
    return rc;
}
