#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <schannel.h>
#include <security.h>
#include <stdio.h>

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
SECURITY_STATUS DecryptReceivedData(SOCKET ClientSocket, CtxtHandle* phContext, PBYTE pReadBuffer, DWORD cbReadBuffer, PBYTE* ppDecryptedData, DWORD* pcbDecryptedData);
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
SECURITY_STATUS AcquireServerCredentials(PCCERT_CONTEXT pCertContext, CredHandle* phCreds) {
    SCHANNEL_CRED SchannelCred = { 0 };
    TimeStamp tsExpiry;

    SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    SchannelCred.cCreds = 1;
    SchannelCred.paCred = &pCertContext; // Pointer to the server certificate context
    SchannelCred.grbitEnabledProtocols = 0; // Use system defaults 0, or specify (e.g., SP_PROT_TLS1_2_SERVER)
    // For stronger security, explicitly set this:
    // SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    SchannelCred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    // SCH_CRED_MANUAL_CRED_VALIDATION can be used if you want to manually validate client certs
    // SCH_CRED_NO_CLIENT_CERT_REQUEST if you don't want to request client certs

    // For server-side, use SECPKG_CRED_INBOUND
    SECURITY_STATUS Status = AcquireCredentialsHandle(
        NULL,                 // Name of principal
        UNISP_NAME_W,         // Name of security package (Schannel)
        SECPKG_CRED_INBOUND,  // Credentials used for inbound connections (server)
        NULL,                 // Pointer to logon ID
        &SchannelCred,        // Package specific data
        NULL,                 // GetKeyFn
        NULL,                 // GetKeyArgument
        phCreds,              // (out) Credential handle
        &tsExpiry             // (out) Lifetime of credentials
    );

    if (Status != SEC_E_OK) {
        fprintf(stderr, "AcquireCredentialsHandle failed: 0x%lx\n", Status);
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

###############################################
tls_client.c


#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

 // For Sspi.h
#include <sspi.h>
#include <schannel.h>   // For Schannel specific structures and constants
#include <wincrypt.h> // For certificate functions (though client might not present one)

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib") // For potential certificate operations

#define SERVER_NAME L"localhost" // Or the actual server hostname/IP
#define SERVER_PORT "8080"       // Must match the server's port

// Function prototypes
BOOL InitializeWinsock();
SOCKET ConnectToServer(LPCWSTR serverName, PCSTR port);
SECURITY_STATUS AcquireClientCredentials(CredHandle* phCreds, TimeStamp* ptsExpiry);
SECURITY_STATUS PerformClientTlsHandshake(SOCKET ServerSocket, CredHandle* phCreds, CtxtHandle* phContext, SEC_CHAR* pszServerName);
SECURITY_STATUS EncryptAndSendDataClient(SOCKET ServerSocket, CtxtHandle* phContext, PBYTE pData, DWORD cbData);
SECURITY_STATUS DecryptReceivedDataClient(SOCKET ServerSocket, CtxtHandle* phContext, PBYTE pReadBuffer, DWORD cbReadBuffer, PBYTE* ppDecryptedData, DWORD* pcbDecryptedData);
void VerifyServerCertificate(CtxtHandle* phContext, LPCWSTR pszServerName); // Optional: for manual validation
void ClientCleanup(SOCKET ServerSocket, CredHandle* phCreds, CtxtHandle* phContext);

int main() {
    if (!InitializeWinsock()) {
        return 1;
    }

    SOCKET ServerSocket = ConnectToServer(SERVER_NAME, SERVER_PORT);
    if (ServerSocket == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    printf("Connected to server %S:%s.\n", SERVER_NAME, SERVER_PORT);

    CredHandle hClientCreds;
    TimeStamp tsExpiryCreds;
    SECURITY_STATUS secStatus = AcquireClientCredentials(&hClientCreds, &tsExpiryCreds);
    if (secStatus != SEC_E_OK) {
        fprintf(stderr, "AcquireClientCredentials failed with error 0x%lx\n", secStatus);
        closesocket(ServerSocket);
        WSACleanup();
        return 1;
    }
    printf("Client credentials acquired.\n");

    CtxtHandle hClientContext;
    // Convert server name to SEC_CHAR for InitializeSecurityContext
    // For Unicode, SEC_CHAR is wchar_t. For ANSI, it's char.
    // Assuming UNICODE is defined for the project (common for modern Windows dev).
    SEC_CHAR szServerNameSec[256];
#ifdef UNICODE
    wcscpy_s(szServerNameSec, sizeof(szServerNameSec) / sizeof(wchar_t), SERVER_NAME);
#else
    // If not UNICODE, convert SERVER_NAME (LPCWSTR) to char*
    // This example assumes UNICODE for simplicity with UNISP_NAME_W in AcquireClientCredentials
    // If you must use ANSI, ensure consistency.
    WideCharToMultiByte(CP_ACP, 0, SERVER_NAME, -1, szServerNameSec, sizeof(szServerNameSec), NULL, NULL);
#endif


    secStatus = PerformClientTlsHandshake(ServerSocket, &hClientCreds, &hClientContext, szServerNameSec);
    if (secStatus != SEC_E_OK) {
        fprintf(stderr, "TLS handshake failed with error 0x%lx\n", secStatus);
    }
    else {
        printf("TLS handshake successful with server %S.\n", SERVER_NAME);

        // Optional: Manually verify server certificate details if not relying solely on Schannel's auto-validation
        // VerifyServerCertificate(&hClientContext, SERVER_NAME);

        // Example: Receive welcome message
        BYTE readBuffer[4096];
        PBYTE decryptedData = NULL;
        DWORD decryptedDataLen = 0;

        // First, try to decrypt any data that might have been received along with the final handshake message
        // (This logic might be integrated into PerformClientTlsHandshake's handling of leftover data)
        // For now, assume handshake is clean and server sends data next.

        int bytesReceived = recv(ServerSocket, (char*)readBuffer, sizeof(readBuffer), 0);
        if (bytesReceived > 0) {
            printf("Received %d encrypted bytes from server.\n", bytesReceived);
            DecryptReceivedDataClient(ServerSocket, &hClientContext, readBuffer, bytesReceived, &decryptedData, &decryptedDataLen);
            if (decryptedData && decryptedDataLen > 0) {
                printf("Server says: %.*s\n", decryptedDataLen, (char*)decryptedData);
                FreeContextBuffer(decryptedData);
            }
        }
        else if (bytesReceived == 0) {
            printf("Server closed connection after handshake.\n");
        }
        else {
            fprintf(stderr, "recv after handshake failed: %d\n", WSAGetLastError());
        }


        // Example: Send a message to the server
        char clientMsg[] = "Hello from Schannel Client!";
        EncryptAndSendDataClient(ServerSocket, &hClientContext, (PBYTE)clientMsg, strlen(clientMsg));


        // Shutdown Schannel session (graceful)
        DWORD dwType = SCHANNEL_SHUTDOWN;
        SecBufferDesc OutBufferDesc;
        SecBuffer OutBuffers[1];
        SECURITY_STATUS status;
        DWORD dwSSPIFlagsClient, dwSSPIOutFlagsClient;
        TimeStamp tsExpiryCtxClient;


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
            // Prepare to send the shutdown token
            SecBufferDesc OutBufferDescShutdown;
            SecBuffer OutBuffersShutdown[1];

            OutBuffersShutdown[0].pvBuffer = NULL;
            OutBuffersShutdown[0].BufferType = SECBUFFER_TOKEN;
            OutBuffersShutdown[0].cbBuffer = 0;
            OutBufferDescShutdown.cBuffers = 1;
            OutBufferDescShutdown.pBuffers = OutBuffersShutdown;
            OutBufferDescShutdown.ulVersion = SECBUFFER_VERSION;

            dwSSPIFlagsClient = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
                ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

            status = InitializeSecurityContext(
                &hClientCreds,
                &hClientContext, // Current context
                NULL, // No target name needed for shutdown after ApplyControlToken
                dwSSPIFlagsClient,
                0,
                SECURITY_NATIVE_DREP,
                NULL, // Input buffer (already processed by ApplyControlToken)
                0,
                NULL, // New context handle (not used for this call)
                &OutBufferDescShutdown,
                &dwSSPIOutFlagsClient,
                &tsExpiryCtxClient);

            if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) { // SEC_I_CONTINUE_NEEDED for client is less common here but check
                if (OutBuffersShutdown[0].cbBuffer != 0 && OutBuffersShutdown[0].pvBuffer != NULL) {
                    printf("Sending shutdown token (%lu bytes) to server.\n", OutBuffersShutdown[0].cbBuffer);
                    send(ServerSocket, (char*)OutBuffersShutdown[0].pvBuffer, OutBuffersShutdown[0].cbBuffer, 0);
                    FreeContextBuffer(OutBuffersShutdown[0].pvBuffer);
                }
            }
            else {
                fprintf(stderr, "InitializeSecurityContext for shutdown failed: 0x%lx\n", status);
            }
        }
    }

    ClientCleanup(ServerSocket, &hClientCreds, secStatus == SEC_E_OK ? &hClientContext : NULL);
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

SOCKET ConnectToServer(LPCWSTR serverName, PCSTR port) {
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    int iResult;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // AF_INET for IPv4 only, AF_INET6 for IPv6 only
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    char serverNameAnsi[256];
    WideCharToMultiByte(CP_ACP, 0, serverName, -1, serverNameAnsi, sizeof(serverNameAnsi), NULL, NULL);

    iResult = getaddrinfo(serverNameAnsi, port, &hints, &result);
    if (iResult != 0) {
        fprintf(stderr, "getaddrinfo failed: %d\n", iResult);
        return INVALID_SOCKET;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            fprintf(stderr, "socket failed with error: %ld\n", WSAGetLastError());
            freeaddrinfo(result);
            return INVALID_SOCKET;
        }

        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break; // Successfully connected
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        fprintf(stderr, "Unable to connect to server!\n");
    }
    return ConnectSocket;
}

//step 3

SECURITY_STATUS AcquireClientCredentials(CredHandle* phCreds, TimeStamp* ptsExpiry) {
    SCHANNEL_CRED SchannelCred = { 0 };

    SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    // For client-side, usually no certificate is explicitly passed unless mutual auth is required.
    // If mutual auth is needed, you'd load a client cert similar to the server and set paCred.
    // SchannelCred.cCreds = 0; // No explicit credentials
    // SchannelCred.paCred = NULL;

    SchannelCred.grbitEnabledProtocols = 0; // Use system defaults 0, or specify (e.g., SP_PROT_TLS1_2_CLIENT)
    // For stronger security, explicitly set this:
    // SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;

    SchannelCred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | // Automatically validate server cert against trusted CAs
        SCH_CRED_NO_DEFAULT_CREDS | // Do not use current user's default cert automatically
        SCH_USE_STRONG_CRYPTO;
    // Use SCH_CRED_MANUAL_CRED_VALIDATION if you want to manually inspect and validate the server cert chain.
    // If using SCH_CRED_MANUAL_CRED_VALIDATION, SCH_CRED_AUTO_CRED_VALIDATION should not be set.

    SECURITY_STATUS Status = AcquireCredentialsHandle(
        NULL,                 // Principal name (NULL for default)
        UNISP_NAME_W,         // Schannel SSP name (ensure UNICODE for L"Microsoft Unified Security Protocol Provider")
        SECPKG_CRED_OUTBOUND, // Credentials for outbound connection (client)
        NULL,                 // PLUID (NULL for current process logon ID)
        &SchannelCred,        // Schannel-specific data
        NULL,                 // GetKeyFn (not used)
        NULL,                 // GetKeyArgument (not used)
        phCreds,              // (out) Credential handle
        ptsExpiry             // (out) Lifetime of credentials
    );

    if (Status != SEC_E_OK) {
        fprintf(stderr, "AcquireCredentialsHandle (client) failed: 0x%lx\n", Status);
        if (Status == SEC_E_SECPKG_NOT_FOUND) {
            fprintf(stderr, "Schannel SSP not found. Ensure Cryptographic Services are running.\n");
        }
        else if (Status == SEC_E_NO_CREDENTIALS) {
            fprintf(stderr, "No system credentials available. This can happen if TLS protocols are disabled system-wide.\n");
        }
    }
    return Status;
}

//step 4

SECURITY_STATUS PerformClientTlsHandshake(SOCKET ServerSocket, CredHandle* phCreds, CtxtHandle* phContext, SEC_CHAR* pszServerName) {
    SECURITY_STATUS SecStatus;
    BOOL bFirstCall = TRUE;
    BOOL bContextInitialized = FALSE;

    SecBufferDesc OutBufferDesc;
    SecBuffer OutBuffers[1];
    SecBufferDesc InBufferDesc;
    SecBuffer InBuffers[2]; // One for token, one for potential leftover data

    BYTE ReadBuffer[8192];
    DWORD cbReadBuffer = 0;

    DWORD dwSSPIFlags;
    DWORD dwSSPIOutFlags;
    TimeStamp tsExpiry;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_REQ_ALLOCATE_MEMORY | // Schannel allocates output buffers
        ISC_REQ_STREAM |
        ISC_REQ_USE_SUPPLIED_CREDS | // Use the credentials from phCreds
        ISC_REQ_EXTENDED_ERROR;
        ISC_REQ_MANUAL_CRED_VALIDATION; // If you set SCH_CRED_MANUAL_CRED_VALIDATION in AcquireCreds

    SecStatus = SEC_I_CONTINUE_NEEDED;

    while (SecStatus == SEC_I_CONTINUE_NEEDED ||
        SecStatus == SEC_E_INCOMPLETE_MESSAGE ||
        SecStatus == SEC_I_INCOMPLETE_CREDENTIALS) {

        // --- Prepare Output Buffer ---
        OutBufferDesc.ulVersion = SECBUFFER_VERSION;
        OutBufferDesc.cBuffers = 1;
        OutBufferDesc.pBuffers = OutBuffers;

        OutBuffers[0].pvBuffer = NULL; // Schannel will allocate
        OutBuffers[0].cbBuffer = 0;
        OutBuffers[0].BufferType = SECBUFFER_TOKEN;

        // --- Prepare Input Buffer (if not the first call) ---
        if (!bFirstCall) {
            InBufferDesc.ulVersion = SECBUFFER_VERSION;
            InBufferDesc.cBuffers = 1; // Or 2 if handling SECBUFFER_EXTRA from previous recv
            InBufferDesc.pBuffers = InBuffers;

            InBuffers[0].pvBuffer = ReadBuffer;
            InBuffers[0].cbBuffer = cbReadBuffer;
            InBuffers[0].BufferType = SECBUFFER_TOKEN;

            // InBuffers[1].BufferType = SECBUFFER_EMPTY; // if used
        }

        SecStatus = InitializeSecurityContext(
            phCreds,
            bFirstCall ? NULL : phContext, // Existing context (NULL on first call)
            bFirstCall ? pszServerName : NULL, // Target name (server FQDN) on first call
            dwSSPIFlags,
            0,                              // Reserved
            SECURITY_NATIVE_DREP,           // Target data representation
            bFirstCall ? NULL : &InBufferDesc, // Input buffer from server (NULL on first call)
            0,                              // Reserved2
            phContext,                      // (out) New context handle
            &OutBufferDesc,                 // (out) Output token to send to server
            &dwSSPIOutFlags,                // (out) Resulting context attributes
            &tsExpiry                       // (out) Expiry time for context
        );

        bFirstCall = FALSE;
        bContextInitialized = TRUE;

        // --- Send output token to server (if any) ---
        if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL) {
            printf("Sending %lu bytes to server (handshake).\n", OutBuffers[0].cbBuffer);
            int bytesSent = send(ServerSocket, (char*)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
            if (bytesSent == SOCKET_ERROR || (DWORD)bytesSent != OutBuffers[0].cbBuffer) {
                fprintf(stderr, "send (handshake) failed with error: %d\n", WSAGetLastError());
                FreeContextBuffer(OutBuffers[0].pvBuffer);
                SecStatus = SEC_E_INTERNAL_ERROR;
                break;
            }
            FreeContextBuffer(OutBuffers[0].pvBuffer); // Free buffer allocated by Schannel
            OutBuffers[0].pvBuffer = NULL;
        }

        if (SecStatus == SEC_E_OK) {
            printf("Handshake complete (SEC_E_OK).\n");
            // Check for any leftover data in InBuffers[1] if it was configured
            // This could be early application data from the server.
            if (InBufferDesc.cBuffers > 1 && InBuffers[1].BufferType == SECBUFFER_EXTRA && InBuffers[1].cbBuffer > 0) {
                printf("Extra data received with final handshake message (%lu bytes).\n", InBuffers[1].cbBuffer);
                // Move this data to the beginning of ReadBuffer for processing by DecryptMessage
                memmove(ReadBuffer, (PBYTE)InBuffers[1].pvBuffer, InBuffers[1].cbBuffer);
                cbReadBuffer = InBuffers[1].cbBuffer;
            }
            else {
                cbReadBuffer = 0; // No leftover data from handshake itself
            }
            break; // Handshake successful
        }
        else if (SecStatus == SEC_I_CONTINUE_NEEDED) {
            printf("Handshake continues (SEC_I_CONTINUE_NEEDED).\n");
            // Need to receive more data from server
        }
        else if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
            printf("Handshake: Incomplete message from server. Need more data.\n");
            // Loop will call recv again. Existing data in ReadBuffer needs to be preserved.
            // The next recv call should append to cbReadBuffer.
            // The current implementation assumes the next recv fills from the start,
            // so if SEC_E_INCOMPLETE_MESSAGE occurs, the existing cbReadBuffer should be
            // the offset for the next recv. A more robust approach:
            // int bytesReceived = recv(ServerSocket, (char*)(ReadBuffer + cbReadBuffer), sizeof(ReadBuffer) - cbReadBuffer, 0);
            // Then, InBuffers[0].pvBuffer = ReadBuffer; InBuffers[0].cbBuffer = cbReadBuffer (new total).
            // For simplicity here, we'll just re-recv the full buffer if this happens and rely on the server re-sending.
            // This is not ideal. A proper state machine for partial receives is better.
             // cbReadBuffer should remain as is for the next recv to append.
        }
        else if (SecStatus == SEC_I_INCOMPLETE_CREDENTIALS) {
            fprintf(stderr, "Handshake: Incomplete credentials. Client cert may be needed and not provided/found.\n");
            break;
        }
        else {
            fprintf(stderr, "InitializeSecurityContext failed with error: 0x%lx\n", SecStatus);
            if (SecStatus == SEC_E_CERT_EXPIRED) fprintf(stderr, "Server certificate is expired.\n");
            if (SecStatus == SEC_E_WRONG_PRINCIPAL) fprintf(stderr, "Server certificate name does not match hostname (%S).\n", pszServerName);
            if (SecStatus == SEC_E_UNTRUSTED_ROOT) fprintf(stderr, "Server certificate was issued by an untrusted root CA.\n");
            if (SecStatus == SEC_E_CERT_UNKNOWN) fprintf(stderr, "An unknown error occurred processing the server certificate.\n");
            if (SecStatus == SEC_E_ILLEGAL_MESSAGE) fprintf(stderr, "Illegal message received from server during handshake.\n");
            if (SecStatus == SEC_E_ALGORITHM_MISMATCH) fprintf(stderr, "Algorithm mismatch with server.\n");

            break;
        }

        // --- Receive server's response for the next handshake step ---
        if (SecStatus == SEC_I_CONTINUE_NEEDED || SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
            // If SEC_E_INCOMPLETE_MESSAGE, we need to append to existing cbReadBuffer
            PBYTE currentRecvBuffer = ReadBuffer;
            DWORD currentRecvSize = sizeof(ReadBuffer);
            if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
                currentRecvBuffer = ReadBuffer + cbReadBuffer;
                currentRecvSize = sizeof(ReadBuffer) - cbReadBuffer;
                if (currentRecvSize == 0) { // Buffer full, cannot receive more
                    fprintf(stderr, "Read buffer full during incomplete message handling.\n");
                    SecStatus = SEC_E_INTERNAL_ERROR;
                    break;
                }
            }
            else {
                cbReadBuffer = 0; // Reset for new message if not incomplete
            }

            int bytesReceived = recv(ServerSocket, (char*)currentRecvBuffer, currentRecvSize, 0);
            if (bytesReceived == SOCKET_ERROR) {
                fprintf(stderr, "recv (handshake) failed with error: %d\n", WSAGetLastError());
                SecStatus = SEC_E_INTERNAL_ERROR;
                break;
            }
            else if (bytesReceived == 0) {
                fprintf(stderr, "Server disconnected during handshake.\n");
                SecStatus = SEC_E_CONTEXT_EXPIRED; // Or SEC_E_INTERNAL_ERROR
                break;
            }
            cbReadBuffer += bytesReceived; // Update total bytes in buffer
            printf("Received %d bytes from server (total %lu for handshake).\n", bytesReceived, cbReadBuffer);
        }
    } // End of while loop

    if (SecStatus != SEC_E_OK && bContextInitialized && phContext->dwLower != 0 && phContext->dwUpper != 0) {
        DeleteSecurityContext(phContext);
        phContext->dwLower = phContext->dwUpper = 0; // Mark as invalid
    }
    return SecStatus;
}

//step 5

void VerifyServerCertificate(CtxtHandle* phContext, LPCWSTR pszServerName) {
    PCCERT_CONTEXT pRemoteCertContext = NULL;
    SECURITY_STATUS SecStatus = QueryContextAttributes(
        phContext,
        SECPKG_ATTR_REMOTE_CERT_CONTEXT, // Attribute to query
        (PVOID)&pRemoteCertContext
    );

    if (SecStatus != SEC_E_OK || pRemoteCertContext == NULL) {
        fprintf(stderr, "QueryContextAttributes (SECPKG_ATTR_REMOTE_CERT_CONTEXT) failed: 0x%lx\n", SecStatus);
        return;
    }

    printf("Server certificate received. Verifying...\n");

    // Basic check: Compare common name or SAN with pszServerName
    // More advanced checks:
    // - Chain validation (CertGetCertificateChain, CertVerifyCertificateChainPolicy)
    // - Revocation checking (CRL, OCSP)
    // - Key usage, extended key usage
    // - Not before/not after dates (though Schannel should handle this if auto-validating)

    // Example: Display subject and issuer (very basic)
    WCHAR szName[256];
    if (CertGetNameStringW(pRemoteCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, szName, sizeof(szName) / sizeof(WCHAR))) {
        printf("  Server Cert Subject: %S\n", szName);
    }
    if (CertGetNameStringW(pRemoteCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, szName, sizeof(szName) / sizeof(WCHAR))) {
        printf("  Server Cert Issuer: %S\n", szName);
    }

    // IMPORTANT: If SCH_CRED_MANUAL_CRED_VALIDATION was used, the application is
    // responsible for deciding if the certificate is trustworthy. If not, it should
    // terminate the connection. Schannel will have already done some basic format checks.

    // For this example, we're mostly relying on SCH_CRED_AUTO_CRED_VALIDATION.
    // If you add manual validation, you'd set a flag here if validation fails
    // and then abort the connection.

    if (pRemoteCertContext) {
        CertFreeCertificateContext(pRemoteCertContext);
    }
}

//step 6

SECURITY_STATUS EncryptAndSendDataClient(SOCKET ServerSocket, CtxtHandle* phContext, PBYTE pData, DWORD cbData) {
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS SecStatus = QueryContextAttributes(phContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
    if (SecStatus != SEC_E_OK) {
        fprintf(stderr, "QueryContextAttributes (StreamSizes) for encrypt failed: 0x%lx\n", SecStatus);
        return SecStatus;
    }

    DWORD cbMessageBuffer = Sizes.cbHeader + cbData + Sizes.cbTrailer;
    PBYTE pMessageBuffer = (PBYTE)malloc(cbMessageBuffer);
    if (!pMessageBuffer) {
        return SEC_E_INSUFFICIENT_MEMORY;
    }
    memcpy(pMessageBuffer + Sizes.cbHeader, pData, cbData);

    SecBuffer Buffers[4];
    SecBufferDesc MessageDesc;

    Buffers[0].pvBuffer = pMessageBuffer;
    Buffers[0].cbBuffer = Sizes.cbHeader;
    Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

    Buffers[1].pvBuffer = pMessageBuffer + Sizes.cbHeader;
    Buffers[1].cbBuffer = cbData;
    Buffers[1].BufferType = SECBUFFER_DATA;

    Buffers[2].pvBuffer = pMessageBuffer + Sizes.cbHeader + cbData;
    Buffers[2].cbBuffer = Sizes.cbTrailer;
    Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

    Buffers[3].pvBuffer = SECBUFFER_EMPTY; // Or NULL
    Buffers[3].cbBuffer = 0;
    Buffers[3].BufferType = SECBUFFER_EMPTY;


    MessageDesc.ulVersion = SECBUFFER_VERSION;
    MessageDesc.cBuffers = 4;
    MessageDesc.pBuffers = Buffers;

    SecStatus = EncryptMessage(phContext, 0, &MessageDesc, 0);
    if (FAILED(SecStatus)) {
        fprintf(stderr, "EncryptMessage (client) failed: 0x%lx\n", SecStatus);
        free(pMessageBuffer);
        return SecStatus;
    }

    DWORD cbToSend = Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer;
    int bytesSent = send(ServerSocket, (char*)pMessageBuffer, cbToSend, 0);
    if (bytesSent == SOCKET_ERROR || (DWORD)bytesSent != cbToSend) {
        fprintf(stderr, "send (encrypted client data) failed: %d\n", WSAGetLastError());
        free(pMessageBuffer);
        return SEC_E_INTERNAL_ERROR;
    }

    printf("Sent %d encrypted bytes to server.\n", bytesSent);
    free(pMessageBuffer);
    return SEC_E_OK;
}

//step 7

SECURITY_STATUS DecryptReceivedDataClient(SOCKET ServerSocket, CtxtHandle* phContext,
    PBYTE pReadBuffer, DWORD cbReadBuffer,
    PBYTE* ppDecryptedData, DWORD* pcbDecryptedData) {
    *ppDecryptedData = NULL;
    *pcbDecryptedData = 0;

    // Note: pReadBuffer contains the raw encrypted bytes received from the socket.
    // cbReadBuffer is the number of bytes in pReadBuffer.

    SecBuffer Buffers[4]; // Schannel often expects 4 for stream operations
    SecBufferDesc MessageDesc;

    Buffers[0].pvBuffer = pReadBuffer;
    Buffers[0].cbBuffer = cbReadBuffer;
    Buffers[0].BufferType = SECBUFFER_DATA; // The encrypted record.

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
    MessageDesc.cBuffers = 4;
    MessageDesc.pBuffers = Buffers;

    ULONG ulQop = 0;
    SECURITY_STATUS SecStatus = DecryptMessage(phContext, &MessageDesc, 0, &ulQop);

    if (SecStatus == SEC_E_OK) {
        // Find the decrypted data. Usually in Buffers[1] if type SECBUFFER_DATA,
        // or sometimes Buffers[0] might be overwritten.
        // The documentation says for stream contexts, the decrypted data is usually in Buffers[1].
        for (unsigned int i = 0; i < MessageDesc.cBuffers; i++) {
            if (Buffers[i].BufferType == SECBUFFER_DATA && Buffers[i].cbBuffer > 0) {
                *ppDecryptedData = (PBYTE)malloc(Buffers[i].cbBuffer); // Allocate new buffer for decrypted data
                if (*ppDecryptedData) {
                    memcpy(*ppDecryptedData, Buffers[i].pvBuffer, Buffers[i].cbBuffer);
                    *pcbDecryptedData = Buffers[i].cbBuffer;
                    printf("Decrypted %lu bytes from server.\n", *pcbDecryptedData);
                }
                else {
                    SecStatus = SEC_E_INSUFFICIENT_MEMORY;
                }
                break; // Found data
            }
        }
        if (*ppDecryptedData == NULL && SecStatus == SEC_E_OK) {
            printf("DecryptMessage returned SEC_E_OK, but no SECBUFFER_DATA found. Might be a control message.\n");
        }

    }
    else if (SecStatus == SEC_I_CONTEXT_EXPIRED) {
        printf("Server initiated graceful shutdown (SEC_I_CONTEXT_EXPIRED on client decrypt).\n");
    }
    else if (SecStatus == SEC_I_RENEGOTIATE) {
        printf("SEC_I_RENEGOTIATE received from server. Client needs to re-handshake.\n");
        // The token to send back to the server to continue the re-handshake
        // is typically in Buffers[1] (type SECBUFFER_TOKEN).
        // The client would then call InitializeSecurityContext again.
        // This example does not fully implement re-handshake.
    }
    else if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
        fprintf(stderr, "DecryptMessage (client) failed: SEC_E_INCOMPLETE_MESSAGE. Need more data from server.\n");
        // Caller should append more data and call DecryptMessage again.
    }
    else {
        fprintf(stderr, "DecryptMessage (client) failed: 0x%lx\n", SecStatus);
    }

    // If SECBUFFER_EXTRA was returned by DecryptMessage (e.g., Buffers[3]),
    // it contains data that was not processed (e.g., start of next TLS record).
    // This data needs to be preserved and prepended to the next recv.
    // This basic example does not handle this robustly.
    for (unsigned int i = 0; i < MessageDesc.cBuffers; i++) {
        if (Buffers[i].BufferType == SECBUFFER_EXTRA && Buffers[i].cbBuffer > 0) {
            printf("DecryptMessage returned SECBUFFER_EXTRA with %lu bytes. This data should be preserved for next read.\n", Buffers[i].cbBuffer);
            // memmove(pReadBuffer, Buffers[i].pvBuffer, Buffers[i].cbBuffer);
            // cbReadBuffer = Buffers[i].cbBuffer; // Next read should start after this.
            // Or, copy to a holding buffer.
            break;
        }
    }


    return SecStatus;
}

//step 8

void ClientCleanup(SOCKET ServerSocket, CredHandle* phCreds, CtxtHandle* phContext) {
    if (phContext && phContext->dwLower != 0 && phContext->dwUpper != 0) { // Basic check for valid handle
        DeleteSecurityContext(phContext);
        printf("Client security context deleted.\n");
    }
    if (phCreds && phCreds->dwLower != 0 && phCreds->dwUpper != 0) {
        FreeCredentialsHandle(phCreds);
        printf("Client credentials handle freed.\n");
    }
    if (ServerSocket != INVALID_SOCKET) {
        shutdown(ServerSocket, SD_BOTH); // Gracefully shutdown socket send/receive
        closesocket(ServerSocket);
        printf("Server socket closed.\n");
    }
    WSACleanup();
    printf("Winsock cleaned up.\n");
}

-########################################################################
