#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int connect_tls(SSL *ssl, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(port)};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
        SSL_set_fd(ssl, fd) != 1 || SSL_connect(ssl) != 1) exit(3);
    return fd;
}

static void request(SSL *ssl, int phase) {
    char req[128], response[4096];
    int n = snprintf(req, sizeof(req), "GET /phase-%d HTTP/1.1\r\nHost: localhost\r\n\r\n", phase);
    if (phase & 1) {
        size_t written = 0;
        if (SSL_write_ex(ssl, req, (size_t)n, &written) != 1 || written != (size_t)n) exit(4);
    } else if (SSL_write(ssl, req, n) != n) exit(4);
    size_t used = 0;
    for (;;) {
        size_t received = 0;
        if (phase & 1) {
            if (SSL_read_ex(ssl, response + used, sizeof(response) - used - 1, &received) != 1) exit(5);
        } else {
            int count = SSL_read(ssl, response + used, (int)(sizeof(response) - used - 1));
            if (count <= 0) exit(5);
            received = (size_t)count;
        }
        used += received;
        response[used] = 0;
        char *body = strstr(response, "\r\n\r\n");
        if (body && used >= (size_t)(body + 4 - response) + 7) break;
        if (used + 1 == sizeof(response)) exit(6);
    }
    printf("{\"phase\":%d,\"conn\":\"%p\",\"hex\":\"", phase, (void *)ssl);
    for (size_t i = 0; i < used; i++) printf("%02x", (unsigned char)response[i]);
    puts("\"}");
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = ctx ? SSL_new(ctx) : NULL;
    if (!ssl) return 3;
    int port = atoi(argv[1]), fd = connect_tls(ssl, port);
    request(ssl, 0);
    request(ssl, 1);
    SSL_shutdown(ssl);
    close(fd);
    if (SSL_clear(ssl) != 1) return 7;
    fd = connect_tls(ssl, port);
    request(ssl, 2);
    // Same BIOs: OpenSSL keeps the connection; the sensor conservatively
    // rotates capture state at this mutation entry.
    SSL_set_bio(ssl, SSL_get_rbio(ssl), SSL_get_wbio(ssl));
    request(ssl, 3);
    if (SSL_up_ref(ssl) != 1) return 8;
    SSL_free(ssl);
    request(ssl, 4); // Object still exists after reference-count decrement.
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return 0;
}
