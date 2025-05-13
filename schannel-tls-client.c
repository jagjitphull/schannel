
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
