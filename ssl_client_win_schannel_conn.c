// ssl_client_linux.c, compile with -lssk -lcrypto, used to connect the schannel iocp server.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For close()

#include <sys/socket.h>
#include <arpa/inet.h> // For inet_pton, htons, etc.
#include <netdb.h>     // For gethostbyname (optional, direct IP is simpler)

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_IP "192.168.1.68" // Replace with the actual IP of your Windows server
#define SERVER_PORT "8080"               // Must match your Schannel server's port

#define BUFFER_SIZE 8196

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms(); // Or SSL_library_init() for older OpenSSL, OpenSSL_add_all_algorithms is deprecated in newer versions
                                  // For OpenSSL 1.1.0+, SSL_library_init() is called automatically.
                                  // OpenSSL_add_ssl_algorithms() is an alias for OpenSSL_add_all_algorithms()
}

void cleanup_openssl() {
    EVP_cleanup(); // For OpenSSL 1.1.0+, this is also done automatically during SSL_CTX_free etc.
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // Use a method that allows negotiation up to the highest supported version (TLS 1.3 if available)
    method = TLS_client_method(); // General purpose client method

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Optionally, set specific protocol versions (e.g., to only allow TLS 1.2 and 1.3)
    // SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    // SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION); // Or 0 to allow highest

    return ctx;
}

// Function to create a TCP socket and connect
int create_socket_and_connect(const char *hostname, const char *port) {
    int sock;
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            perror("client: connect");
            continue;
        }
        break; // if we get here, we must have connected successfully
    }

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        freeaddrinfo(servinfo);
        return -1;
    }

    freeaddrinfo(servinfo); // all done with this structure
    return sock;
}


int main(int argc, char **argv) {
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;

    const char *server_ip = SERVER_IP;
    const char *server_port_str = SERVER_PORT;

    if (argc > 1) {
        server_ip = argv[1];
    }
    if (argc > 2) {
        server_port_str = argv[2];
    }
    
    if (strcmp(server_ip, "YOUR_WINDOWS_SERVER_IP") == 0) {
        fprintf(stderr, "Please replace YOUR_WINDOWS_SERVER_IP with the actual server IP or pass it as an argument.\n");
        fprintf(stderr, "Usage: %s [server_ip] [server_port]\n", argv[0]);
        return 1;
    }


    init_openssl();
    ctx = create_context();

    // --- Certificate Verification Setup ---
    // By default, OpenSSL tries to verify the peer's certificate.
    // You need to tell it where to find trusted CA certificates.
    // Common paths: /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu) or /etc/pki/tls/certs/ca-bundle.crt (RHEL/CentOS)
    // Or a directory: /etc/ssl/certs
    // SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", NULL);
    // SSL_CTX_set_default_verify_paths(ctx); // Tries to load default system CA paths

    // IMPORTANT: For your Windows Schannel server using a "localhost" certificate:
    // 1. If "localhost" cert is self-signed (as is likely), standard CA verification WILL FAIL.
    // 2. For testing ONLY, you might disable verification. THIS IS INSECURE for production.
    //    To disable (NOT RECOMMENDED FOR PRODUCTION):
    //    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    //    printf("WARNING: Server certificate verification is DISABLED. This is insecure.\n");
    // 3. A better way for a specific self-signed cert is to add THAT cert (or its CA if you made one)
    //    to the client's trust store or load it specifically using SSL_CTX_load_verify_locations.
    //    For this example, we'll demonstrate disabling it for simplicity of connecting to your current server setup.
    //    Comment this out and configure SSL_CTX_load_verify_locations properly for a real scenario.

    printf("Attempting to connect to server with potentially lenient certificate verification for testing.\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // Still request a cert
    // To make it truly lenient for a self-signed cert like "localhost" without loading the CA:
    // You'd need a custom verify_callback or accept specific errors.
    // For now, let's try SSL_VERIFY_NONE for the "localhost" scenario, or show how to skip errors.
    // The most straightforward for a quick test against a self-signed "localhost" cert
    // that is not otherwise trusted by the client OS:
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); // INSECURE - for testing self-signed localhost only
    printf("WARNING: Server certificate verification is effectively DISABLED (SSL_VERIFY_NONE). This is insecure and for testing with self-signed 'localhost' certs ONLY.\n");


    sock = create_socket_and_connect(server_ip, server_port_str);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        cleanup_openssl();
        return 1;
    }
    printf("TCP connected to %s:%s.\n", server_ip, server_port_str);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform the TLS handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed:\n");
        ERR_print_errors_fp(stderr);
    } else {
        printf("SSL/TLS handshake successful with %s:%s.\n", server_ip, server_port_str);
        printf("Negotiated Cipher: %s\n", SSL_get_cipher(ssl));
        printf("Negotiated Protocol: %s\n", SSL_get_version(ssl)); // Note: SSL_get_version might return older names for newer protocols sometimes.

        // --- Send a message to the server ---
        const char *client_msg = "Hello from Linux OpenSSL Client!";
        int bytes_sent = SSL_write(ssl, client_msg, strlen(client_msg));
        if (bytes_sent <= 0) {
            fprintf(stderr, "SSL_write failed:\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("Sent %d bytes to server: %s\n", bytes_sent, client_msg);

            // --- Receive a message from the server ---
            char server_reply[BUFFER_SIZE];
            memset(server_reply, 0, sizeof(server_reply));
            int bytes_received = SSL_read(ssl, server_reply, sizeof(server_reply) - 1);
            if (bytes_received <= 0) {
                int ssl_error = SSL_get_error(ssl, bytes_received);
                fprintf(stderr, "SSL_read failed with SSL_ERROR code: %d\n", ssl_error);
                ERR_print_errors_fp(stderr);
            } else {
                server_reply[bytes_received] = '\0'; // Null-terminate
                printf("Received %d bytes from server: %s\n", bytes_received, server_reply);
            }
        }

        // Graceful shutdown
        SSL_shutdown(ssl);
    }

    // Cleanup
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
