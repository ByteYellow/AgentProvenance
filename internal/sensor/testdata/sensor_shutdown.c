#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <unistd.h>

static atomic_int stopping;
static const char *path;

static void *produce(void *unused) {
    (void)unused;
    while (!atomic_load(&stopping)) {
        int fd = open(path, O_WRONLY);
        if (fd >= 0) close(fd);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    path = argv[1];
    int fd = open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return 2;
    close(fd);
    pthread_t workers[4];
    for (int i = 0; i < 4; i++) {
        if (pthread_create(&workers[i], NULL, produce, NULL)) return 2;
    }
    puts("ready");
    fflush(stdout);
    char stop;
    (void)read(STDIN_FILENO, &stop, 1);
    atomic_store(&stopping, 1);
    for (int i = 0; i < 4; i++) pthread_join(workers[i], NULL);
    return 0;
}
