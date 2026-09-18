// Exercise both legacy SSL_write/read and SSL_write_ex/read_ex C ABIs.
#include <netdb.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) return 2;
	const char *delay = getenv("AGENTPROV_TLS_START_DELAY_SECONDS");
	if (delay && atoi(delay) > 0) sleep((unsigned int)atoi(delay));
	const char *host = getenv("AGENTPROV_TLS_HOST");
	if (!host || !*host) host = "localhost";
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *addr = NULL;
    if (getaddrinfo(host, argv[1], &hints, &addr)) return 3;
    int fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
    if (fd < 0 || connect(fd, addr->ai_addr, addr->ai_addrlen)) return 4;
    freeaddrinfo(addr);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) return 5;
    char body[256], request[1024], response[4096];
    int n = snprintf(body, sizeof(body), "{\"marker\":\"%s\"}", argv[3]);
    int len = snprintf(request, sizeof(request),
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", n, body);
    if (!strcmp(argv[2], "ex")) {
        size_t written = 0, received = 0;
        if (SSL_write_ex(ssl, request, len, &written) != 1 || written != (size_t)len) return 6;
        while (SSL_read_ex(ssl, response, sizeof(response), &received) == 1) {}
    } else {
        if (SSL_write(ssl, request, len) != len) return 7;
        while (SSL_read(ssl, response, sizeof(response)) > 0) {}
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return 0;
}
