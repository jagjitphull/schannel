#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define HOST "127.0.0.1"
#define PORT "8443"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    printf("[DEBUG] OpenSSL initialized.\n");
}

SSL_CTX *create_client_context() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("[DEBUG] SSL context created for client.\n");
    return ctx;
}

void configure_client_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM) <= 0)
        ERR_print_errors_fp(stderr);
    else
        printf("[DEBUG] Client certificate loaded.\n");

    if (SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM) <= 0)
        ERR_print_errors_fp(stderr);
    else
        printf("[DEBUG] Client private key loaded.\n");

    if (!SSL_CTX_check_private_key(ctx))
        fprintf(stderr, "[ERROR] Private key mismatch.\n");

    SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    printf("[DEBUG] Server certificate verification enabled.\n");
}

void dump_tls_info(SSL *ssl) {
    printf("[TLS INFO] Protocol: %s\n", SSL_get_version(ssl));
    printf("[TLS INFO] Cipher: %s\n", SSL_get_cipher(ssl));
    printf("[TLS INFO] Session reused: %s\n", SSL_session_reused(ssl) ? "yes" : "no");
    printf("[TLS INFO] Client session ID: ");
    const SSL_SESSION *sess = SSL_get_session(ssl);
    unsigned int len;
    const unsigned char *sid = SSL_SESSION_get_id(sess, &len);
    for (unsigned int i = 0; i < len; ++i)
        printf("%02X", sid[i]);
    printf("\n");
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_client_context();
    configure_client_context(ctx);

    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    getaddrinfo(HOST, PORT, &hints, &res);

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    connect(sock, res->ai_addr, res->ai_addrlen);
    printf("[DEBUG] Connected to server.\n");
    freeaddrinfo(res);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    printf("[DEBUG] Starting TLS handshake...\n");
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[ERROR] TLS handshake failed:\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("[SUCCESS] TLS handshake completed.\n");
        dump_tls_info(ssl);

        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert) {
            printf("[DEBUG] Server certificate subject: %s\n",
                   X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
            printf("[DEBUG] Server certificate issuer: %s\n",
                   X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0));
            X509_free(cert);
        } else {
            printf("[WARNING] Server did not present a certificate.\n");
        }

        SSL_write(ssl, "Hello from client", strlen("Hello from client"));
        printf("[DEBUG] Message sent to server.\n");

        char buf[256] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        printf("[DEBUG] Server replied: %s\n", buf);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    printf("[DEBUG] Client cleanup complete.\n");
    return 0;
}
