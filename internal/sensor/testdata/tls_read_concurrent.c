// Real OpenSSL reads from 32 threads in one process. Retain SSL objects until
// all readers finish so the byte-for-byte oracle has distinct connection IDs.
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define CLIENTS 32
struct client { SSL *ssl; int fd, id, ex, port; };
static SSL_CTX *ctx;

static void fail(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static void *run(void *arg) {
    struct client *c = arg;
    c->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (c->fd < 0) fail("socket");
    struct timeval timeout = {.tv_sec = 15};
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(c->port)};
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(c->fd, (struct sockaddr *)&addr, sizeof(addr))) fail("connect");
    c->ssl = SSL_new(ctx);
    if (!c->ssl || SSL_set_fd(c->ssl, c->fd) != 1 || SSL_connect(c->ssl) != 1) fail("TLS handshake");
    char request[256], response[4096];
    int len = snprintf(request, sizeof(request),
        "GET /reply-%d HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", c->id);
    if (SSL_write(c->ssl, request, len) != len) fail("TLS write");
    for (;;) {
        size_t received = 0;
        if (c->ex) {
            if (SSL_read_ex(c->ssl, response, sizeof(response), &received) != 1) break;
        } else {
            int n = SSL_read(c->ssl, response, sizeof(response));
            if (n <= 0) break;
            received = (size_t)n;
        }
        flockfile(stdout);
        printf("{\"conn\":\"%p\",\"hex\":\"", (void *)c->ssl);
        for (size_t i = 0; i < received; i++) printf("%02x", (unsigned char)response[i]);
        puts("\"}");
        funlockfile(stdout);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) fail("TLS context");
    struct client clients[CLIENTS];
    pthread_t threads[CLIENTS];
    int mode = atoi(argv[2]);
    for (int i = 0; i < CLIENTS; i++) {
        clients[i] = (struct client){.fd = -1, .id = i, .ex = mode == 2 ? i % 2 : mode, .port = atoi(argv[1])};
        if (pthread_create(&threads[i], NULL, run, &clients[i])) fail("thread create");
    }
    for (int i = 0; i < CLIENTS; i++) {
        if (pthread_join(threads[i], NULL)) fail("thread join");
    }
    for (int i = 0; i < CLIENTS; i++) {
        SSL_free(clients[i].ssl);
        close(clients[i].fd);
    }
    SSL_CTX_free(ctx);
    return 0;
}
