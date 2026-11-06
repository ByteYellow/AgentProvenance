// Real HTTPS keepalive: one exact-size SSL write followed by a small request.
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void exchange(SSL *ssl, const char *data, int n, int ex) {
    if (ex) {
        size_t written = 0;
        if (SSL_write_ex(ssl, data, (size_t)n, &written) != 1 || written != (size_t)n) exit(4);
    } else if (SSL_write(ssl, data, n) != n) exit(4);
    char response[1024];
    size_t used = 0;
    for (;;) {
        int received = SSL_read(ssl, response + used, (int)(sizeof(response) - used - 1));
        if (received <= 0) exit(5);
        used += (size_t)received;
        response[used] = 0;
        char *body = strstr(response, "\r\n\r\n");
        if (body && used >= (size_t)(body + 4 - response) + 2) return;
        if (used + 1 == sizeof(response)) exit(6);
    }
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    int port = atoi(argv[1]), total = atoi(argv[2]), ex = atoi(argv[3]);
    if (total < 4095 || total > 8192) return 2;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = ctx ? SSL_new(ctx) : NULL;
    if (!ssl || fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1) return 3;
    const char *format = "POST /large HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\n\r\n";
    int header = snprintf(NULL, 0, format, total);
    int body = total - header;
    char *request = malloc((size_t)total + 1);
    if (!request || snprintf(request, (size_t)total + 1, format, body) != header) return 7;
    memset(request + header, 'x', (size_t)body);
    exchange(ssl, request, total, ex);
    const char *next = "GET /after HTTP/1.1\r\nHost: localhost\r\n\r\n";
    exchange(ssl, next, (int)strlen(next), ex);
    printf("%d\n", body);
    free(request);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
