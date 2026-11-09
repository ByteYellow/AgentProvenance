// A private library is loaded after exec; no TLS symbols are linked at startup.
#include <arpa/inet.h>
#include <dlfcn.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LOAD(name) \
    __typeof__(&name) p_##name = (__typeof__(&name))dlsym(lib, #name); \
    if (!p_##name) return 3

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    usleep((useconds_t)atoi(argv[3]) * 1000);
    void *lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 3; }
    LOAD(TLS_client_method);
    LOAD(SSL_CTX_new);
    LOAD(SSL_CTX_free);
    LOAD(SSL_new);
    LOAD(SSL_free);
    LOAD(SSL_set_fd);
    LOAD(SSL_connect);
    LOAD(SSL_write_ex);
    LOAD(SSL_read_ex);
    LOAD(SSL_shutdown);
    usleep((useconds_t)atoi(argv[4]) * 1000);
    SSL_CTX *ctx = p_SSL_CTX_new(p_TLS_client_method());
    SSL *ssl = ctx ? p_SSL_new(ctx) : NULL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[2]))};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (!ssl || fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        p_SSL_set_fd(ssl, fd) != 1 || p_SSL_connect(ssl) != 1) return 4;
    char request[256];
    int n = snprintf(request, sizeof(request), "GET /discovery/%d HTTP/1.1\r\nHost: localhost\r\n\r\n", getpid());
    size_t written = 0;
    if (p_SSL_write_ex(ssl, request, (size_t)n, &written) != 1 || written != (size_t)n) return 5;
    char response[1024];
    size_t used = 0;
    for (;;) {
        size_t received = 0;
        if (p_SSL_read_ex(ssl, response + used, sizeof(response) - used - 1, &received) != 1) return 6;
        used += received;
        response[used] = 0;
        char *body = strstr(response, "\r\n\r\n");
        if (body && used >= (size_t)(body + 4 - response) + 2) break;
        if (used + 1 == sizeof(response)) return 7;
    }
    p_SSL_shutdown(ssl);
    p_SSL_free(ssl);
    p_SSL_CTX_free(ctx);
    close(fd);
    dlclose(lib);
    return 0;
}
