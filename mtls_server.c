/* GEnerating relevant certs for code examples to work
Step 1: Generate the Root CA

openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.pem -subj "/CN=MyTestRootCA"

Step 2: Generate Server Certificate (key + CSR)

openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

Sign Server CSR with CA
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.crt -days 365 -sha256

Step 3: Generate Client Certificate (key + CSR)

openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client"

Step 4: Sign Client CSR with CA
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.crt -days 365 -sha256


Optional: Convert to PFX for Windows Schannel (if needed)

openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt -certfile ca.pem
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt -certfile ca.pem 
*/


#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define PORT 8443

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    printf("[DEBUG] OpenSSL initialized.\n");
}

SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("[DEBUG] SSL context created for server.\n");
    return ctx;
}

void configure_server_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
        ERR_print_errors_fp(stderr);
    else
        printf("[DEBUG] Server certificate loaded.\n");

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
        ERR_print_errors_fp(stderr);
    else
        printf("[DEBUG] Server private key loaded.\n");

    if (!SSL_CTX_check_private_key(ctx))
        fprintf(stderr, "[ERROR] Private key check failed.\n");

    SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);
    printf("[DEBUG] Client certificate verification enabled.\n");
}

void dump_tls_info(SSL *ssl) {
    printf("[TLS INFO] Protocol: %s\n", SSL_get_version(ssl));
    printf("[TLS INFO] Cipher: %s\n", SSL_get_cipher(ssl));
    printf("[TLS INFO] Session reused: %s\n", SSL_session_reused(ssl) ? "yes" : "no");
    printf("[TLS INFO] Server session ID: ");
    const SSL_SESSION *sess = SSL_get_session(ssl);
    unsigned int len;
    const unsigned char *sid = SSL_SESSION_get_id(sess, &len);
    for (unsigned int i = 0; i < len; ++i)
        printf("%02X", sid[i]);
    printf("\n");
}

int main() {
    init_openssl();
    SSL_CTX *ctx = create_server_context();
    configure_server_context(ctx);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 1);
    printf("[DEBUG] Listening on port %d...\n", PORT);

    int client = accept(server_fd, NULL, NULL);
    printf("[DEBUG] Connection accepted.\n");

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    printf("[DEBUG] Beginning TLS handshake...\n");
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "[ERROR] TLS handshake failed:\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("[SUCCESS] TLS handshake complete.\n");
        dump_tls_info(ssl);

        X509 *client_cert = SSL_get_peer_certificate(ssl);
        if (client_cert) {
            printf("[DEBUG] Client certificate subject: %s\n",
                   X509_NAME_oneline(X509_get_subject_name(client_cert), NULL, 0));
            printf("[DEBUG] Client certificate issuer: %s\n",
                   X509_NAME_oneline(X509_get_issuer_name(client_cert), NULL, 0));
            X509_free(client_cert);
        } else {
            printf("[WARNING] Client did not present a certificate.\n");
        }

        char buf[256] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        printf("[DEBUG] Received: %s\n", buf);

        SSL_write(ssl, "Hello from server", strlen("Hello from server"));
        printf("[DEBUG] Reply sent.\n");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
