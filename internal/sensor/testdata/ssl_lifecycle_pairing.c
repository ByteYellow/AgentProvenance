// Synthetic C ABI fixture: deterministic address reuse and a read returning
// after an object reset. No TLS implementation or external traffic is involved.
#include <stdio.h>
#include <string.h>

static int object;
__attribute__((noinline)) void *SSL_new(void *ctx) { (void)ctx; return &object; }
__attribute__((noinline)) void SSL_free(void *ssl) { (void)ssl; }
__attribute__((noinline)) int SSL_clear(void *ssl) { (void)ssl; return 1; }
__attribute__((noinline)) int SSL_write(void *ssl, const void *buf, int n) {
    (void)ssl; (void)buf; return n;
}
__attribute__((noinline)) int SSL_read(void *ssl, void *buf, int n) {
    const char *old = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nold";
    const char *next = "GET /new HTTP/1.1\r\n\r\n";
    SSL_clear(ssl);
    SSL_write(ssl, next, (int)strlen(next));
    if (n < (int)strlen(old)) return -1;
    memcpy(buf, old, strlen(old));
    return (int)strlen(old);
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *ssl = SSL_new(NULL);
    const char *old = "POST /old HTTP/1.1\r\nContent-Length: 9\r\n\r\nold";
    SSL_write(ssl, old, (int)strlen(old));
    if (!strcmp(argv[1], "late-read")) {
        char buf[128];
        SSL_read(ssl, buf, sizeof(buf));
    } else {
        SSL_free(ssl);
        ssl = SSL_new(NULL);
        const char *next = "GET /new HTTP/1.1\r\n\r\n";
        SSL_write(ssl, next, (int)strlen(next));
    }
    SSL_free(ssl);
    return 0;
}
