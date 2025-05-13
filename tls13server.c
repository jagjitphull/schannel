//tls_server - 1.3
#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>
#include <stdio.h>


// Ensure SCH_CREDENTIALS_VERSION is available.
// It's typically in schannel.h or sspi.h for newer SDKs.
// If not, your SDK might be too old, but for Win 10 1809+ it should be there.
#ifndef SCH_CREDENTIALS_VERSION
#define SCH_CREDENTIALS_VERSION 0x00000005 // Common value, but SDK header should provide it
#warning "SCH_CREDENTIALS_VERSION was not defined by SDK headers; using a common default. Check SDK."
#endif



#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

#define SERVER_PORT "8080"
#define CERT_SUBJECT_NAME L"localhost" // Replace with your server's certificate subject name

// Function prototypes
BOOL InitializeWinsock();
SOCKET CreateListenSocket();
PCCERT_CONTEXT FindServerCertificate(LPCWSTR pszSubjectName);
SECURITY_STATUS AcquireServerCredentials(PCCERT_CONTEXT pCertContext, CredHandle* phCreds);
SECURITY_STATUS PerformTlsHandshake(SOCKET ClientSocket, CredHandle* phCreds, CtxtHandle* phContext);
SECURITY_STATUS EncryptAndSendData(SOCKET ClientSocket, CtxtHandle* phContext, PBYTE pData, DWORD cbData);
SECURITY_STATUS DecryptReceivedData(SOCKET ClientSocket, CtxtHandle* phContext, PBYTE pReadBuffer, DWORD cbReadBuffer, PBYTE* ppDecryptedData, 
void QueryAndPrintProtocol(CtxtHandle *phContext, BOOL isServer);DWORD* pcbDecryptedData);
void Cleanup(SOCKET ListenSocket, SOCKET ClientSocket, CredHandle* phCreds, CtxtHandle* phContext);

int main() {
    if (!InitializeWinsock()) {
        return 1;
    }

    SOCKET ListenSocket = CreateListenSocket();
    if (ListenSocket == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    printf("Server listening on port %s...\n", SERVER_PORT);

    PCCERT_CONTEXT pServerCert = FindServerCertificate(CERT_SUBJECT_NAME);
    if (!pServerCert) {
        fprintf(stderr, "Server certificate '%S' not found.\n", CERT_SUBJECT_NAME);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    printf("Server certificate found.\n");

    CredHandle hServerCreds;
    SECURITY_STATUS secStatus = AcquireServerCredentials(pServerCert, &hServerCreds);
    CertFreeCertificateContext(pServerCert); // Release certificate context after acquiring credentials
    if (secStatus != SEC_E_OK) {
        fprintf(stderr, "AcquireServerCredentials failed with error 0x%lx\n", secStatus);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }
    printf("Server credentials acquired.\n");

    while (TRUE) {
        SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);
        if (ClientSocket == INVALID_SOCKET) {
            fprintf(stderr, "accept failed with error: %d\n", WSAGetLastError());
            continue; // Or break depending on desired server behavior
        }
        printf("Client connected.\n");

        CtxtHandle hClientContext;
        secStatus = PerformTlsHandshake(ClientSocket, &hServerCreds, &hClientContext);
        if (secStatus != SEC_E_OK) {
            fprintf(stderr, "TLS handshake failed with error 0x%lx\n", secStatus);
            closesocket(ClientSocket);
        }
        else {
            printf("TLS handshake successful.\n");
            // Example: Send a welcome message
            char welcomeMsg[] = "Hello from Schannel Server!";
            EncryptAndSendData(ClientSocket, &hClientContext, (PBYTE)welcomeMsg, strlen(welcomeMsg));

            // Example: Receive and decrypt data
            BYTE readBuffer[4096];
            PBYTE decryptedData = NULL;
            DWORD decryptedDataLen = 0;
            int bytesReceived = recv(ClientSocket, (char*)readBuffer, sizeof(readBuffer), 0);
            if (bytesReceived > 0) {
                DecryptReceivedData(ClientSocket, &hClientContext, readBuffer, bytesReceived, &decryptedData, &decryptedDataLen);
                if (decryptedData && decryptedDataLen > 0) {
                    printf("Received from client: %.*s\n", decryptedDataLen, (char*)decryptedData);
                    FreeContextBuffer(decryptedData); // Important: Free buffer allocated by DecryptMessage
                }
            }

            // TODO: Implement application-specific data exchange
            // Remember to handle SEC_I_RENEGOTIATE if DecryptMessage returns it.

            // Shutdown Schannel session (graceful)
            DWORD dwType = SCHANNEL_SHUTDOWN;
            SecBufferDesc OutBufferDesc;
            SecBuffer OutBuffers[1];
            SECURITY_STATUS status;

            OutBuffers[0].pvBuffer = &dwType;
            OutBuffers[0].BufferType = SECBUFFER_TOKEN;
            OutBuffers[0].cbBuffer = sizeof(dwType);

            OutBufferDesc.cBuffers = 1;
            OutBufferDesc.pBuffers = OutBuffers;
            OutBufferDesc.ulVersion = SECBUFFER_VERSION;

            status = ApplyControlToken(&hClientContext, &OutBufferDesc);
            if (FAILED(status)) {
                fprintf(stderr, "ApplyControlToken (SCHANNEL_SHUTDOWN) failed: 0x%lx\n", status);
            }
            else {
                // The output token (if any) from ApplyControlToken is then sent to the client by calling AcceptSecurityContext
                // This prepares the token to be sent.
                SecBufferDesc InBufferDesc;
                SecBuffer InBuffers[1];
                SecBufferDesc OutBufferDescShutdown;
                SecBuffer OutBuffersShutdown[1];
                DWORD dwSSPIFlags;
                DWORD dwSSPIOutFlags;
                TimeStamp tsExpiry;

                InBuffers[0].pvBuffer = &dwType; // This might be optional or context-dependent after ApplyControlToken
                InBuffers[0].cbBuffer = sizeof(dwType);
                InBuffers[0].BufferType = SECBUFFER_TOKEN;
                InBufferDesc.cBuffers = 1;
                InBufferDesc.pBuffers = InBuffers;
                InBufferDesc.ulVersion = SECBUFFER_VERSION;


                OutBuffersShutdown[0].pvBuffer = NULL;
                OutBuffersShutdown[0].BufferType = SECBUFFER_TOKEN;
                OutBuffersShutdown[0].cbBuffer = 0;
                OutBufferDescShutdown.cBuffers = 1;
                OutBufferDescShutdown.pBuffers = OutBuffersShutdown;
                OutBufferDescShutdown.ulVersion = SECBUFFER_VERSION;

                dwSSPIFlags = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_REPLAY_DETECT | ASC_REQ_SEQUENCE_DETECT | ASC_REQ_STREAM;

                status = AcceptSecurityContext(
                    &hServerCreds,
                    &hClientContext, // existing context
                    NULL, // No input token from client for this notification
                    dwSSPIFlags,
                    SECURITY_NATIVE_DREP,
                    NULL, // new context handle not needed for shutdown notification
                    &OutBufferDescShutdown,
                    &dwSSPIOutFlags,
                    &tsExpiry);

                if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
                    if (OutBuffersShutdown[0].cbBuffer != 0 && OutBuffersShutdown[0].pvBuffer != NULL) {
                        send(ClientSocket, (char*)OutBuffersShutdown[0].pvBuffer, OutBuffersShutdown[0].cbBuffer, 0);
                        FreeContextBuffer(OutBuffersShutdown[0].pvBuffer);
                    }
                }
            }

            DeleteSecurityContext(&hClientContext);
            printf("Client context deleted.\n");
        }
        closesocket(ClientSocket);
        printf("Client socket closed.\n");
    }

    Cleanup(ListenSocket, INVALID_SOCKET, &hServerCreds, NULL);
    return 0;
}

BOOL InitializeWinsock() {
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", iResult);
        return FALSE;
    }
    return TRUE;
}


//step 2

SOCKET CreateListenSocket() {
    SOCKET ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) {
        fprintf(stderr, "socket failed with error: %ld\n", WSAGetLastError());
        return INVALID_SOCKET;
    }

    struct sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    service.sin_port = htons(atoi(SERVER_PORT));

    if (bind(ListenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        return INVALID_SOCKET;
    }

    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        return INVALID_SOCKET;
    }
    return ListenSocket;
}

//step 3

PCCERT_CONTEXT FindServerCertificate(LPCWSTR pszSubjectName) {
    HCERTSTORE hMyCertStore = NULL;
    PCCERT_CONTEXT pServerCert = NULL;

    // Open the "MY" certificate store for the local machine.
    hMyCertStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        0,
        0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE,
        L"MY");

    if (!hMyCertStore) {
        fprintf(stderr, "CertOpenStore failed with error 0x%lx\n", GetLastError());
        return NULL;
    }

    // Find the certificate by subject name.
    pServerCert = CertFindCertificateInStore(
        hMyCertStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR_W,
        pszSubjectName,
        NULL); // Find first match

    if (!pServerCert) {
        fprintf(stderr, "CertFindCertificateInStore failed to find '%S' (Error: 0x%lx).\n", pszSubjectName, GetLastError());
    }

    if (CertCloseStore(hMyCertStore, 0) == 0) {
        fprintf(stderr, "CertCloseStore failed with error 0x%lx\n", GetLastError());
    }
    // Note: If pServerCert is found, the caller is responsible for freeing it with CertFreeCertificateContext
    return pServerCert;
}

//step 4
// In server.c

// Ensure SCH_CREDENTIALS_VERSION is available.
// It's typically in schannel.h or sspi.h for newer SDKs.
// If not, your SDK might be too old, but for Win 10 1809+ it should be there.
#ifndef SCH_CREDENTIALS_VERSION
#define SCH_CREDENTIALS_VERSION 0x00000005 // Common value, but SDK header should provide it
#warning "SCH_CREDENTIALS_VERSION was not defined by SDK headers; using a common default. Check SDK."
#endif

SECURITY_STATUS AcquireServerCredentials(PCCERT_CONTEXT pCertContext, CredHandle *phCreds) {
    SCH_CREDENTIALS SchannelCred = {0}; // Use the new structure
    TimeStamp tsExpiry;

    SchannelCred.dwVersion = SCH_CREDENTIALS_VERSION; // Use the new version identifier
    SchannelCred.dwCredFormat = SCH_CRED_FORMAT_CERT_CONTEXT; // We are using a certificate context

    SchannelCred.cCreds = 1;
    SchannelCred.paCred = &pCertContext; // Pointer to the server certificate context

    // dwFlags:
    // SCH_CRED_NO_DEFAULT_CREDS - Do not automatically use current user's default certs.
    // SCH_USE_STRONG_CRYPTO - Enforce strong cryptography.
    // SCH_CRED_MANUAL_CRED_VALIDATION - If you want the server to manually validate client certs (if requested).
    //                                   (Remove if not doing mutual auth or if auto-validating client certs)
    SchannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    if (/* your condition to require and manually validate client certs */ 0) { // Example placeholder
         SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    // hRootStore = NULL: Use the system's default trust stores for validating client certs (if applicable).
    SchannelCred.hRootStore = NULL;

    // Other fields can often be zero for default behavior in simple scenarios
    SchannelCred.cMappers = 0;
    SchannelCred.aphMappers = NULL;
    SchannelCred.dwSessionLifespan = 0; // Default session lifespan
    SchannelCred.dwTlsSecretsFlags = 0; // Default behavior for TLS 1.3 secrets

    // Note: grbitEnabledProtocols is NOT a member of SCH_CREDENTIALS.
    // Protocol selection relies on OS configuration (registry).

    SECURITY_STATUS Status = AcquireCredentialsHandle(
        NULL,                 // Name of principal
        UNISP_NAME_W,         // Name of security package (Schannel)
        SECPKG_CRED_INBOUND,  // Credentials used for inbound connections (server)
        NULL,                 // Pointer to logon ID
        &SchannelCred,        // Package specific data (now SCH_CREDENTIALS)
        NULL,                 // GetKeyFn
        NULL,                 // GetKeyArgument
        phCreds,              // (out) Credential handle
        &tsExpiry             // (out) Lifetime of credentials
    );

    if (Status != SEC_E_OK) {
        fprintf(stderr, "Server: AcquireCredentialsHandle failed with SCH_CREDENTIALS: 0x%lx\n", Status);
    } else {
        printf("Server: Credentials acquired successfully using SCH_CREDENTIALS.\n");
    }
    return Status;
}

//step 5

SECURITY_STATUS PerformTlsHandshake(SOCKET ClientSocket, CredHandle* phCreds, CtxtHandle* phContext) {
    SECURITY_STATUS SecStatus;
    BOOL bFirstCall = TRUE;
    BOOL bContextInitialized = FALSE; // To know if DeleteSecurityContext is needed on failure

    SecBufferDesc OutBufferDesc;
    SecBuffer OutBuffers[1];
    SecBufferDesc InBufferDesc;
    SecBuffer InBuffers[2]; // Use two input buffers: one for token, one for Schannel to report extra

    BYTE ReadBuffer[8192];    // Buffer to hold raw data from client
    DWORD cbReadBuffer = 0;   // Number of valid bytes currently in ReadBuffer (leftover or newly read)

    DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    TimeStamp tsExpiry;

    // Standard flags for server-side AcceptSecurityContext
    dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
        ASC_REQ_REPLAY_DETECT |
        ASC_REQ_CONFIDENTIALITY |
        ASC_REQ_EXTENDED_ERROR |
        ASC_REQ_ALLOCATE_MEMORY | // Schannel allocates output buffers for token to send
        ASC_REQ_STREAM;
    // Add ASC_REQ_MUTUAL_AUTH if you require client certificates

    SecStatus = SEC_I_CONTINUE_NEEDED; // Initial status to enter the loop

    printf("Server: Starting TLS Handshake Loop...\n");

    while (SecStatus == SEC_I_CONTINUE_NEEDED ||
        SecStatus == SEC_E_INCOMPLETE_MESSAGE ||
        SecStatus == SEC_I_INCOMPLETE_CREDENTIALS) { // SEC_I_INCOMPLETE_CREDENTIALS if waiting for client cert

        // --- 1. Read data from client if needed ---
        if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
            // We have a partial message in ReadBuffer (up to cbReadBuffer). Need to read more.
            if (cbReadBuffer >= sizeof(ReadBuffer)) {
                fprintf(stderr, "Server: ReadBuffer full but message still incomplete. Cannot proceed.\n");
                SecStatus = SEC_E_INTERNAL_ERROR; // Or a more specific error
                break;
            }
            printf("Server: SEC_E_INCOMPLETE_MESSAGE. Current cbReadBuffer = %lu. Attempting to read more data...\n", cbReadBuffer);
            int bytesReceived = recv(ClientSocket, (char*)(ReadBuffer + cbReadBuffer), sizeof(ReadBuffer) - cbReadBuffer, 0);
            if (bytesReceived == SOCKET_ERROR) {
                fprintf(stderr, "Server: recv failed with error (incomplete_message): %d\n", WSAGetLastError());
                SecStatus = SEC_E_INTERNAL_ERROR; // Or map Winsock error
                break;
            }
            else if (bytesReceived == 0) {
                fprintf(stderr, "Server: Client disconnected during incomplete message read.\n");
                SecStatus = SEC_E_CONTEXT_EXPIRED; // Or SEC_E_INTERNAL_ERROR
                break;
            }
            cbReadBuffer += bytesReceived;
            printf("Server: Received %d more bytes. New cbReadBuffer = %lu.\n", bytesReceived, cbReadBuffer);
        }
        else if (cbReadBuffer == 0) {
            // No leftover data and not an incomplete message, so read fresh from client
            printf("Server: cbReadBuffer is 0. Attempting to read fresh data...\n");
            int bytesReceived = recv(ClientSocket, (char*)ReadBuffer, sizeof(ReadBuffer), 0);
            if (bytesReceived == SOCKET_ERROR) {
                fprintf(stderr, "Server: recv failed with error (fresh_read): %d\n", WSAGetLastError());
                SecStatus = SEC_E_INTERNAL_ERROR;
                break;
            }
            else if (bytesReceived == 0) {
                fprintf(stderr, "Server: Client disconnected before sending initial handshake data.\n");
                SecStatus = SEC_E_CONTEXT_EXPIRED;
                break;
            }
            cbReadBuffer = bytesReceived;
            printf("Server: Received %lu fresh bytes.\n", cbReadBuffer);
        }
        // If cbReadBuffer > 0 here, it's either a complete new read,
        // an appended incomplete message, or leftover data from a previous successful step.

        // --- 2. Prepare input buffers for AcceptSecurityContext ---
        InBufferDesc.ulVersion = SECBUFFER_VERSION;
        InBufferDesc.cBuffers = 2; // Using two buffers for more robust leftover data handling
        InBufferDesc.pBuffers = InBuffers;

        InBuffers[0].pvBuffer = ReadBuffer;
        InBuffers[0].cbBuffer = cbReadBuffer; // Pass all currently held data
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer = NULL; // Second buffer for Schannel to potentially report extra data
        InBuffers[1].cbBuffer = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        // --- 3. Prepare output buffer for AcceptSecurityContext (token to send to client) ---
        OutBufferDesc.ulVersion = SECBUFFER_VERSION;
        OutBufferDesc.cBuffers = 1;
        OutBufferDesc.pBuffers = OutBuffers;

        OutBuffers[0].pvBuffer = NULL; // Schannel will allocate memory if it has a token to send
        OutBuffers[0].cbBuffer = 0;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;

        printf("Server: Calling AcceptSecurityContext. cbReadBuffer = %lu, InBuffers[0].cbBuffer = %lu\n",
            cbReadBuffer, InBuffers[0].cbBuffer);

        // --- 4. Call AcceptSecurityContext ---
        SecStatus = AcceptSecurityContext(
            phCreds,
            bFirstCall ? NULL : phContext, // Context handle: NULL on first call
            &InBufferDesc,                 // Input buffer(s) from client
            dwSSPIFlags,                   // Context requirements
            SECURITY_NATIVE_DREP,          // Target data representation
            phContext,                     // (out) New context handle (if first call successful)
            &OutBufferDesc,                // (out) Output token to send to client
            &dwSSPIOutFlags,               // (out) Resulting context attributes
            &tsExpiry                      // (out) Expiry time for context
        );

        printf("Server: AcceptSecurityContext returned 0x%lx.\n", SecStatus);
        bContextInitialized = TRUE; // Context has been touched, might need cleanup
        if (!bFirstCall && phContext->dwLower == 0 && phContext->dwUpper == 0 && SecStatus != SEC_E_OK && SecStatus != SEC_I_CONTINUE_NEEDED && SecStatus != SEC_I_INCOMPLETE_CREDENTIALS) {
            // This can happen if an existing context becomes invalid
            printf("Server: Context handle appears to have been invalidated by AcceptSecurityContext failure.\n");
        }


        bFirstCall = FALSE; // All subsequent calls are not the first

        // --- 5. Send output token to client (if any) ---
        if (SecStatus == SEC_E_OK || SecStatus == SEC_I_CONTINUE_NEEDED || SecStatus == SEC_I_INCOMPLETE_CREDENTIALS) {
            if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL) {
                printf("Server: Sending %lu bytes token to client.\n", OutBuffers[0].cbBuffer);
                int bytesSent = send(ClientSocket, (char*)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
                if (bytesSent == SOCKET_ERROR || (DWORD)bytesSent != OutBuffers[0].cbBuffer) {
                    fprintf(stderr, "Server: send of handshake token failed with error: %d\n", WSAGetLastError());
                    FreeContextBuffer(OutBuffers[0].pvBuffer); // Must free what Schannel allocated
                    SecStatus = SEC_E_INTERNAL_ERROR; // Or a more specific error
                    break; // Exit handshake loop on send error
                }
                FreeContextBuffer(OutBuffers[0].pvBuffer); // Free buffer allocated by Schannel
                OutBuffers[0].pvBuffer = NULL;
            }
        }

        // --- 6. Process results and manage leftover input data ---
        if (SecStatus == SEC_E_OK) {
            printf("Server: Handshake complete (SEC_E_OK).\n");
            QueryAndPrintProtocol(&hClientContext, TRUE); // TRUE for server
            // Check for any leftover data that might be early application data
            if (InBuffers[1].BufferType == SECBUFFER_EXTRA && InBuffers[1].cbBuffer > 0) {
                printf("Server: SECBUFFER_EXTRA found in InBuffers[1] after SEC_E_OK (%lu bytes). This is early app data.\n", InBuffers[1].cbBuffer);
                MoveMemory(ReadBuffer, InBuffers[1].pvBuffer, InBuffers[1].cbBuffer);
                cbReadBuffer = InBuffers[1].cbBuffer;
            }
            else if (InBuffers[0].BufferType == SECBUFFER_TOKEN && InBuffers[0].cbBuffer > 0 && (PBYTE)InBuffers[0].pvBuffer != ReadBuffer && cbReadBuffer > InBuffers[0].cbBuffer) {
                // This case implies Schannel might have advanced the pvBuffer in InBuffers[0] and updated cbBuffer
                // to reflect the remaining part, and no SECBUFFER_EXTRA in InBuffers[1].
                // Schannel didn't consume all of InBuffers[0] and didn't use InBuffers[1].
                printf("Server: Unconsumed data in InBuffers[0] after SEC_E_OK (%lu bytes). This is early app data.\n", InBuffers[0].cbBuffer);

                MoveMemory(ReadBuffer, InBuffers[0].pvBuffer, InBuffers[0].cbBuffer);
                cbReadBuffer = InBuffers[0].cbBuffer;
            }
            else if (InBuffers[0].BufferType == SECBUFFER_TOKEN && InBuffers[0].cbBuffer > 0 && (PBYTE)InBuffers[0].pvBuffer == ReadBuffer) {
                // Schannel indicates data remains in InBuffers[0] but didn't advance the pointer.
                // This is less common for SEC_E_OK if the whole message fit.
                // If cbReadBuffer was the original size, and InBuffers[0].cbBuffer is smaller, there's a delta.
                // However, for SEC_E_OK, it's safer to assume if InBuffers[1] is not SECBUFFER_EXTRA, all was consumed or handled.
                // For simplicity after SEC_E_OK, if InBuffers[1] isn't extra, assume consumed or handled.
                printf("Server: InBuffers[0] still has data after SEC_E_OK but InBuffers[1] not extra. Assuming consumed or error in logic.\n");
                cbReadBuffer = 0; // Default to consumed if logic is unclear here for SEC_E_OK
            }
            else {
                cbReadBuffer = 0; // All consumed or no clear leftover in input buffers
            }
            break; // Handshake successful, exit loop
        
        /*   if ((PBYTE)InBuffers[0].pvBuffer != ReadBuffer) { // Pointer might have been advanced by Schannel
                    MoveMemory(ReadBuffer, InBuffers[0].pvBuffer, InBuffers[0].cbBuffer);
                }
                cbReadBuffer = InBuffers[0].cbBuffer;
            }
            else {
                cbReadBuffer = 0; // All consumed
            }
            break; // Handshake successful, exit loop
        } */
        } else if (SecStatus == SEC_I_CONTINUE_NEEDED || SecStatus == SEC_I_INCOMPLETE_CREDENTIALS) {
            printf("Server: Handshake continues (0x%lx).\n", SecStatus);
            // The token that was in InBuffers[0] (e.g., ClientHello) has been successfully processed.
            // We now check if Schannel reported any *additional* data that was part of the same client send
            // (e.g., if client pipelined data, rare for handshake but SECBUFFER_EXTRA handles it).
            // Handshake is ongoing. Check for leftover data from this step.
            if (InBuffers[1].BufferType == SECBUFFER_EXTRA && InBuffers[1].cbBuffer > 0) {
                printf("Server: SECBUFFER_EXTRA found in InBuffers[1] after CONTINUE (%lu bytes).\n", InBuffers[1].cbBuffer);
                MoveMemory(ReadBuffer, InBuffers[1].pvBuffer, InBuffers[1].cbBuffer);
                cbReadBuffer = InBuffers[1].cbBuffer;   // This is the start of the NEXT client message.
            }
            else {
                // No SECBUFFER_EXTRA reported. This means all of InBuffers[0] was consumed for the *current*
                // handshake step (e.g., the entire ClientHello). We now need to receive the *next distinct*
                // message from the client. So, clear cbReadBuffer to trigger a fresh recv().
                printf("Server: No SECBUFFER_EXTRA after CONTINUE. Setting cbReadBuffer to 0 to await next client message.\n");
                cbReadBuffer = 0;
            }
        } else if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
            printf("Server: SEC_E_INCOMPLETE_MESSAGE. cbReadBuffer (%lu) holds current partial data. Loop will read more.\n", cbReadBuffer);
            // IMPORTANT: Do NOT reset cbReadBuffer here. The existing data in ReadBuffer is the
            // start of the message, and the next iteration's recv() will append to it.
            // Ensure ReadBuffer has enough space: sizeof(ReadBuffer) - cbReadBuffer.
        }
        else {
            // Any other SecStatus is a failure
            fprintf(stderr, "Server: AcceptSecurityContext failed with unrecoverable error: 0x%lx\n", SecStatus);
            cbReadBuffer = 0; // No valid data to carry over
            break; // Exit handshake loop
        }
    } // End of while loop

    printf("Server: Exiting TLS Handshake Loop with SecStatus = 0x%lx.\n", SecStatus);

    // If loop exited due to an error (and not SEC_E_OK), and context was partially formed, clean it up.
    // Note: phContext would be NULL if the very first call to ASC failed before initializing it.
    if (SecStatus != SEC_E_OK && bContextInitialized && phContext && (phContext->dwLower != 0 || phContext->dwUpper != 0)) {
        DeleteSecurityContext(phContext);
        // Clear the handle to prevent reuse if this function is somehow re-entered with the same pointer
        // phContext->dwLower = 0; 
        // phContext->dwUpper = 0; 
        printf("Server: Deleted partially formed security context due to handshake error.\n");
    }

    return SecStatus;
}

//step 6

SECURITY_STATUS EncryptAndSendData(SOCKET ClientSocket, CtxtHandle* phContext, PBYTE pData, DWORD cbData) {
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS SecStatus = QueryContextAttributes(phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    if (SecStatus != SEC_E_OK) {
        fprintf(stderr, "QueryContextAttributes (StreamSizes) failed: 0x%lx\n", SecStatus);
        return SecStatus;
    }

    // Allocate a buffer large enough for header, data, and trailer
    DWORD cbMessageBuffer = Sizes.cbHeader + cbData + Sizes.cbTrailer;
    PBYTE pMessageBuffer = (PBYTE)malloc(cbMessageBuffer);
    if (!pMessageBuffer) {
        return SEC_E_INSUFFICIENT_MEMORY;
    }

    // Copy plaintext application data into the buffer, leaving space for header
    memcpy(pMessageBuffer + Sizes.cbHeader, pData, cbData);

    SecBuffer Buffers[4]; // As per documentation for Schannel stream contexts
    SecBufferDesc MessageDesc;

    // Header
    Buffers[0].pvBuffer = pMessageBuffer;
    Buffers[0].cbBuffer = Sizes.cbHeader;
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    // Data
    Buffers[1].pvBuffer = pMessageBuffer + Sizes.cbHeader;
    Buffers[1].cbBuffer = cbData;
    Buffers[1].BufferType = SECBUFFER_DATA;

    // Trailer
    Buffers[2].pvBuffer = pMessageBuffer + Sizes.cbHeader + cbData;
    Buffers[2].cbBuffer = Sizes.cbTrailer;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    // Empty (Schannel may use this for other purposes)
    Buffers[3].pvBuffer = SECBUFFER_EMPTY;
    Buffers[3].cbBuffer = SECBUFFER_EMPTY;
    Buffers[3].BufferType = SECBUFFER_EMPTY;


    MessageDesc.ulVersion = SECBUFFER_VERSION;
    MessageDesc.cBuffers = 4;
    MessageDesc.pBuffers = Buffers;

    SecStatus = EncryptMessage(phContext, 0, &MessageDesc, 0);
    if (FAILED(SecStatus)) {
        fprintf(stderr, "EncryptMessage failed: 0x%lx\n", SecStatus);
        free(pMessageBuffer);
        return SecStatus;
    }

    // Send the encrypted data (header + encrypted data + trailer)
    // The actual encrypted data is now in Buffers[0].pvBuffer through Buffers[2].pvBuffer combined
    // Total bytes to send: Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer
    DWORD cbToSend = Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer;

    int bytesSent = send(ClientSocket, (char*)pMessageBuffer, cbToSend, 0);
    if (bytesSent == SOCKET_ERROR || (DWORD)bytesSent != cbToSend) {
        fprintf(stderr, "send (encrypted) failed: %d\n", WSAGetLastError());
        free(pMessageBuffer);
        return SEC_E_INTERNAL_ERROR; // Or a more specific Winsock error
    }

    printf("Sent %d encrypted bytes.\n", bytesSent);
    free(pMessageBuffer);
    return SEC_E_OK;
}

//step 7

SECURITY_STATUS DecryptReceivedData(SOCKET ClientSocket, CtxtHandle* phContext,
    PBYTE pReadBuffer, DWORD cbReadBuffer,
    PBYTE* ppDecryptedData, DWORD* pcbDecryptedData) {
    *ppDecryptedData = NULL;
    *pcbDecryptedData = 0;

    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS SecStatus = QueryContextAttributes(phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    if (SecStatus != SEC_E_OK) {
        fprintf(stderr, "QueryContextAttributes (StreamSizes) for decrypt failed: 0x%lx\n", SecStatus);
        return SecStatus;
    }

    // Prepare buffers for DecryptMessage.
    // The received data (pReadBuffer) is one SSL/TLS record.
    // DecryptMessage will decrypt it in place if possible, or indicate where data is.
    SecBuffer Buffers[4]; // Typically 1 data buffer, others might be for header/trailer info or extra data.
    SecBufferDesc MessageDesc;

    Buffers[0].pvBuffer = pReadBuffer;
    Buffers[0].cbBuffer = cbReadBuffer;
    Buffers[0].BufferType = SECBUFFER_DATA; // The encrypted record.

    // Schannel might need additional buffers for context. For stream, it's often 4.
    // Some may be marked SECBUFFER_EMPTY initially.
    Buffers[1].BufferType = SECBUFFER_EMPTY;
    Buffers[1].cbBuffer = 0;
    Buffers[1].pvBuffer = NULL;

    Buffers[2].BufferType = SECBUFFER_EMPTY;
    Buffers[2].cbBuffer = 0;
    Buffers[2].pvBuffer = NULL;

    Buffers[3].BufferType = SECBUFFER_EMPTY;
    Buffers[3].cbBuffer = 0;
    Buffers[3].pvBuffer = NULL;


    MessageDesc.ulVersion = SECBUFFER_VERSION;
    MessageDesc.cBuffers = 4; // Schannel often expects 4 for stream operations
    MessageDesc.pBuffers = Buffers;

    ULONG ulQop = 0; // Quality of Protection (output)

    SecStatus = DecryptMessage(phContext, &MessageDesc, 0, &ulQop);

    if (SecStatus == SEC_E_OK) {
        // Find the decrypted data buffer.
        // DecryptMessage decrypts in-place or provides a pointer.
        // Usually, the SECBUFFER_DATA buffer (Buffers[0] here initially)
        // might be modified, or one of the SECBUFFER_EXTRA buffers will point to data.
        // Look for the buffer of type SECBUFFER_DATA that now holds the plaintext.
        for (unsigned int i = 0; i < MessageDesc.cBuffers; i++) {
            if (Buffers[i].BufferType == SECBUFFER_DATA) {
                *ppDecryptedData = (PBYTE)malloc(Buffers[i].cbBuffer);
                if (*ppDecryptedData) {
                    memcpy(*ppDecryptedData, Buffers[i].pvBuffer, Buffers[i].cbBuffer);
                    *pcbDecryptedData = Buffers[i].cbBuffer;
                    printf("Decrypted %lu bytes.\n", *pcbDecryptedData);
                }
                else {
                    SecStatus = SEC_E_INSUFFICIENT_MEMORY;
                }
                break;
            }
        }
        if (*ppDecryptedData == NULL && SecStatus == SEC_E_OK) {
            // This can happen if DecryptMessage processes a TLS alert (like close_notify)
            // but returns SEC_E_OK without application data.
            printf("DecryptMessage returned SEC_E_OK, but no SECBUFFER_DATA found. Might be a control message.\n");
        }

    }
    else if (SecStatus == SEC_I_CONTEXT_EXPIRED) {
        // Client initiated shutdown. This is a normal way to close.
        printf("Client initiated graceful shutdown (SEC_I_CONTEXT_EXPIRED).\n");
        // No application data in this case.
    }
    else if (SecStatus == SEC_I_RENEGOTIATE) {
        // Server needs to re-negotiate the security context.
        // This means calling AcceptSecurityContext again.
        // The token to send to the client might be in one of the buffers (e.g., type SECBUFFER_TOKEN or SECBUFFER_EXTRA).
        printf("SEC_I_RENEGOTIATE received from DecryptMessage. Need to re-handshake.\n");
        // TODO: Handle renegotiation by looping back to AcceptSecurityContext logic,
        // using the token found in MessageDesc.pBuffers (usually in Buffers[1] if type is SECBUFFER_TOKEN).
    }
    else if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
        fprintf(stderr, "DecryptMessage failed: SEC_E_INCOMPLETE_MESSAGE. Need more data from client.\n");
        // Caller should append more data and call DecryptMessage again with the combined buffer.
    }
    else {
        fprintf(stderr, "DecryptMessage failed: 0x%lx\n", SecStatus);
    }

    // Note: If DecryptMessage allocates memory for ppDecryptedData (e.g. if it were SECBUFFER_EXTRA),
    // it would typically be freed with FreeContextBuffer. Here, we malloc/memcpy for clarity.
    // If SECBUFFER_DATA was decrypted in-place in pReadBuffer, no separate free is needed for *ppDecryptedData if it points into pReadBuffer.
    // However, our example allocates a new buffer for *ppDecryptedData.

    return SecStatus;
}


void QueryAndPrintProtocol(CtxtHandle *phContext, BOOL isServer) {
    SecPkgContext_ConnectionInfo ConnectionInfo;
    SECURITY_STATUS SecStatus = QueryContextAttributes(
        phContext,
        SECPKG_ATTR_CONNECTION_INFO, // Attribute to query
        &ConnectionInfo
    );

    if (SecStatus != SEC_E_OK) {
        fprintf(stderr, "%s: QueryContextAttributes (SECPKG_ATTR_CONNECTION_INFO) failed: 0x%lx\n",
                isServer ? "Server" : "Client", SecStatus);
        return;
    }

    printf("%s: Negotiated Protocol: ", isServer ? "Server" : "Client");
    switch (ConnectionInfo.dwProtocol) {
        case SP_PROT_TLS1_3_CLIENT: printf("TLS 1.3 (Client Active)\n"); break;
        case SP_PROT_TLS1_3_SERVER: printf("TLS 1.3 (Server Active)\n"); break;
        case SP_PROT_TLS1_2_CLIENT: printf("TLS 1.2 (Client Active)\n"); break;
        case SP_PROT_TLS1_2_SERVER: printf("TLS 1.2 (Server Active)\n"); break;
        case SP_PROT_TLS1_1_CLIENT: printf("TLS 1.1 (Client Active)\n"); break;
        case SP_PROT_TLS1_1_SERVER: printf("TLS 1.1 (Server Active)\n"); break;
        case SP_PROT_TLS1_0_CLIENT: printf("TLS 1.0 (Client Active)\n"); break;
        case SP_PROT_TLS1_0_SERVER: printf("TLS 1.0 (Server Active)\n"); break;
        // Add older SSL protocols if needed for some reason, though they are insecure
        default: printf("Unknown or older protocol (0x%lx)\n", ConnectionInfo.dwProtocol); break;
    }

    printf("%s: Negotiated Cipher: 0x%lx (Algorithm: %u, Strength: %u bits)\n",
           isServer ? "Server" : "Client",
           ConnectionInfo.dwCipher,
           ConnectionInfo.aiCipher,
           ConnectionInfo.dwCipherStrength);
    // You might need to map ConnectionInfo.aiCipher to a human-readable name (e.g., CALG_AES_256)
    // and ConnectionInfo.dwCipher to a TLS cipher suite name.
}

//step 8

void Cleanup(SOCKET ServerSocket, CredHandle* phCreds, CtxtHandle* phContext) {
    // Check if the context handle appears to be initialized before trying to delete
    if (phContext && (phContext->dwLower != 0 || phContext->dwUpper != 0)) {
        DeleteSecurityContext(phContext);
        printf("Client security context deleted.\n");
        // Optionally, zero out the handle after freeing
        // phContext->dwLower = 0;
        // phContext->dwUpper = 0;
    }

    // Check if the credentials handle appears to be initialized before trying to free
    if (phCreds && (phCreds->dwLower != 0 || phCreds->dwUpper != 0)) {
        FreeCredentialsHandle(phCreds);
        printf("Client credentials handle freed.\n");
        // Optionally, zero out the handle after freeing
        // phCreds->dwLower = 0;
        // phCreds->dwUpper = 0;
    }

    if (ServerSocket != INVALID_SOCKET) {
        shutdown(ServerSocket, SD_BOTH);
        closesocket(ServerSocket);
        printf("Server socket closed.\n");
    }
    WSACleanup();
    printf("Winsock cleaned up.\n");
}
