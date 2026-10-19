// Synthetic C-ABI probe fixture, not an OpenSSL implementation. It exercises
// nesting and exceptional returns that real HTTPS clients rarely produce.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct call {
    int depth, limit, ex;
    const char *mode;
};

static void report(void *conn, const char *buf, size_t n) {
    flockfile(stdout);
    printf("{\"conn\":\"%p\",\"hex\":\"", conn);
    for (size_t i = 0; i < n; i++) printf("%02x", (unsigned char)buf[i]);
    puts("\"}");
    funlockfile(stdout);
}

__attribute__((noinline)) int SSL_read(void *ssl, void *buf, int num);
__attribute__((noinline)) int SSL_read_ex(void *ssl, void *buf, size_t num, size_t *received);

static int body(struct call *call, void *buf, size_t num) {
    if (!strcmp(call->mode, "exit")) pthread_exit(NULL);
    if (!strcmp(call->mode, "exec")) {
        execl("/proc/self/exe", "ssl_read_pairing", "normal", "1", call->ex ? "1" : "0", NULL);
        _exit(5);
    }
    if (!strcmp(call->mode, "failure") && call->depth == 1) return -1;
    if (!strcmp(call->mode, "oversize")) return (int)num + 1;
    if (call->depth + 1 < call->limit) {
        struct call child = *call;
        child.depth++;
        char nested[128];
        if (call->ex) {
            size_t received = 0;
            SSL_read_ex(&child, nested, sizeof(nested), &received);
        } else {
            SSL_read(&child, nested, sizeof(nested));
        }
    }
    int n = snprintf(buf, num, "depth=%d ex=%d", call->depth, call->ex);
    if (n <= 0 || (size_t)n >= num) abort();
    // Only the first four frames are retained by the bounded sensor stack.
    if (call->depth < 4) report(call, buf, (size_t)n);
    return n;
}

__attribute__((noinline)) int SSL_read(void *ssl, void *buf, int num) {
    return body(ssl, buf, (size_t)num);
}

__attribute__((noinline)) int SSL_read_ex(void *ssl, void *buf, size_t num, size_t *received) {
    struct call *call = ssl;
    if (!strcmp(call->mode, "bad-out")) return 1;
    int n = body(call, buf, num);
    if (n <= 0) return 0;
    *received = (size_t)n;
    return 1;
}

static void *run(void *arg) {
    struct call *call = arg;
    char buf[128];
    size_t received = 0;
    if (call->ex) {
        size_t *out = !strcmp(call->mode, "bad-out") ? (size_t *)(uintptr_t)1 : &received;
        SSL_read_ex(call, buf, sizeof(buf), out);
    } else {
        SSL_read(call, buf, sizeof(buf));
    }
    // Verify normal use after a failed/overflowing read in the same thread.
    call->depth = 0;
    call->limit = 1;
    call->mode = "normal";
    if (call->ex) SSL_read_ex(call, buf, sizeof(buf), &received);
    else SSL_read(call, buf, sizeof(buf));
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    struct call call = {.limit = atoi(argv[2]), .ex = atoi(argv[3]), .mode = argv[1]};
    pthread_t thread;
    if (pthread_create(&thread, NULL, run, &call)) return 3;
    if (pthread_join(thread, NULL)) return 4;
    return 0;
}
