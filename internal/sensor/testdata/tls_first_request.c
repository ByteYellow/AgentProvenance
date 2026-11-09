#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const char *port = strrchr(argv[1], ':');
    if (!port) return 3;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(port + 1)),
    };
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (void *)&address, sizeof(address))) return 4;
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // Loopback fixture only.
    SSL *ssl = SSL_new(ctx);
    if (!SSL_set_fd(ssl, fd) || SSL_connect(ssl) != 1) return 5;
    const char request[] =
        "GET /first-request HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if (SSL_write(ssl, request, sizeof(request) - 1) != (int)sizeof(request) - 1)
        return 6;
    char body[1024];
    if (SSL_read(ssl, body, sizeof(body)) <= 0) return 7;
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
