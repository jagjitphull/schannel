// SchannelServer_IOCP.c
// Testing the code - 
//  1) Execute this program exe on one terminal
//  2) openssl s_client -connect 192.168.1.68:8080 ( where IP is server IP).

// Standard practice: winsock2.h before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h> // For AcceptEx
#include <windows.h>
#include <winternl.h>

#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <sspi.h>     // For SCH_CREDENTIALS, SCH_CREDENTIALS_VERSION etc.
#include <schannel.h> // Includes sspi.h again, but it's fine.
#include <wincrypt.h> // For certificate functions

#include <stdio.h>
#include <stdlib.h> // For malloc, free
#include <assert.h> // For assert

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Crypt32.lib")

#define SERVER_PORT "8080"
#define LISTEN_IP_ADDRESS "0.0.0.0" // Bind to all interfaces, or specify one like "192.168.1.100"
#define CERT_SUBJECT_NAME_A "localhost" // ANSI version for FindServerCertificate if UNICODE is not strictly used
#define UNISP_NAME_A "Microsoft Unified Security Protocol Provider"


#define BUFFER_SIZE 8192
#define MAX_SCHANNEL_RECV_BUFFER_SIZE (1024 * 20) // Schannel tokens can be > 16KB
#define DEFAULT_WORKER_THREAD_COUNT (SystemInfo.dwNumberOfProcessors * 2)

// Ensure SCH_CREDENTIALS_VERSION is defined (should be in sspi.h for modern SDKs)
#ifndef SCH_CREDENTIALS_VERSION
#define SCH_CREDENTIALS_VERSION 0x00000005
#pragma message("Warning: SCH_CREDENTIALS_VERSION was not defined by SDK headers; using a common default. Check SDK version and include order.")
#endif

// --- Global Variables ---
HANDLE g_hIoCompletionPort = NULL;
CredHandle g_hServerCreds;
BOOL g_bServerRunning = TRUE;
LPFN_ACCEPTEX g_lpfnAcceptEx = NULL;
SOCKET g_ListenSocket = INVALID_SOCKET;

#define LISTEN_SOCKET_COMPLETION_KEY ((ULONG_PTR)1) // A unique key for accept completions
#define CLIENT_SOCKET_COMPLETION_KEY ((ULONG_PTR)2) // Base for client keys, though we use pointer

// --- Structures ---
typedef enum _IO_OPERATION {
    IO_INITIALIZE,       // Placeholder for initial setup if needed
    IO_ACCEPT,
    IO_READ,
    IO_WRITE,
    IO_READ_HANDSHAKE,
    IO_WRITE_HANDSHAKE,
    IO_READ_ENCRYPTED_APP,
    IO_WRITE_ENCRYPTED_APP,
    IO_SHUTDOWN
 } IO_OPERATION;

typedef struct _PER_SOCKET_CONTEXT PER_SOCKET_CONTEXT, * PPER_SOCKET_CONTEXT;

typedef struct _PER_IO_CONTEXT {
    OVERLAPPED Overlapped;
    WSABUF WSABuf;
    char   Buffer[BUFFER_SIZE];     // General purpose buffer for this I/O
    IO_OPERATION OperationType;
    PPER_SOCKET_CONTEXT pSocketContext; // For ESTABLISHED connections, points to its owner
    SOCKET AcceptSocket;            // For IO_ACCEPT, stores the newly created accepted socket FOR THIS OP
    DWORD  TotalBytesToSend;
    DWORD  BytesSentSoFar;
} PER_IO_CONTEXT, * PPER_IO_CONTEXT;

struct _PER_SOCKET_CONTEXT {
    SOCKET Socket;
    CredHandle* pServerCredsHandle; // Pointer to global server credentials
    CtxtHandle SchannelContext;
    BOOL SchannelContextInitialized;

    BYTE   SchannelAccumulatedRecvBuffer[MAX_SCHANNEL_RECV_BUFFER_SIZE];
    DWORD  cbSchannelAccumulatedRecvBuffer;

    // State for Schannel handshake
    BOOL   HandshakeInProgress;
    BOOL   HandshakeComplete;
    BOOL   bFirstSchannelCall; // For AcceptSecurityContext
    SecPkgContext_StreamSizes StreamSizes;

    PER_IO_CONTEXT ReadIoContext;  // Embedded for simplicity for one pending read
    PER_IO_CONTEXT WriteIoContext; // Embedded for simplicity for one pending write

    // Other application-specific state can go here
};

// --- Function Prototypes ---
BOOL InitializeWinsock();
BOOL InitializeIOCP();
BOOL InitializeSchannel(); // Wrapper for FindServerCertificate & AcquireServerCredentials
PCCERT_CONTEXT FindServerCertificateByName(LPCSTR pszSubjectNameA); // Changed to ANSI
SECURITY_STATUS AcquireServerCredentialsSCH(PCCERT_CONTEXT pCertContext, CredHandle* phCreds);
DWORD WINAPI WorkerThread(LPVOID lpParam);
BOOL PostAccept(PPER_IO_CONTEXT pAcceptIoContext);
//BOOL PostAccept(SOCKET ListenSocket, PPER_IO_CONTEXT pAcceptIoContext);
BOOL PostRecv(PPER_SOCKET_CONTEXT pSocketContext);
BOOL PostSend(PPER_SOCKET_CONTEXT pSocketContext, PBYTE pbData, DWORD cbData, IO_OPERATION opType);
void HandleAcceptCompletion(PPER_SOCKET_CONTEXT pSocketContextForNewConnection, PPER_IO_CONTEXT pAcceptIoContext);
void HandleReadCompletion(PPER_SOCKET_CONTEXT pSocketContext, DWORD dwBytesTransferred);
void HandleWriteCompletion(PPER_SOCKET_CONTEXT pSocketContext, PPER_IO_CONTEXT pIoWriteContext, DWORD dwBytesTransferred);
void ProcessSchannelHandshake(PPER_SOCKET_CONTEXT pSocketContext);
void ProcessEncryptedAppData(PPER_SOCKET_CONTEXT pSocketContext, DWORD dwDataLen); // Placeholder
void QueryAndPrintProtocol(CtxtHandle* phContext, BOOL isServer); // From previous
void CloseClientConnection(PPER_SOCKET_CONTEXT pSocketContext, BOOL bGracefulSchannelShutdown);


// --- Main Function ---
int main() {
    if (!InitializeWinsock()) return 1;
    if (!InitializeIOCP()) return 1;
    if (!InitializeSchannel()) return 1; // Loads cert, acquires creds into g_hServerCreds

    //SOCKET ListenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    g_ListenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED); // USE GLOBAL

    if (g_ListenSocket == INVALID_SOCKET) {
        fprintf(stderr, "WSASocket(g_ListenSocket) failed: %d\n", WSAGetLastError());
        // Proper cleanup of already initialized parts (IOCP, g_hServerCreds)
        if (g_hIoCompletionPort) CloseHandle(g_hIoCompletionPort);
        if (g_hServerCreds.dwLower || g_hServerCreds.dwUpper) FreeCredentialsHandle(&g_hServerCreds);
        WSACleanup();
        return 1;
    }

    // Bind
    struct sockaddr_in service;
    service.sin_family = AF_INET;
    if (inet_pton(AF_INET, LISTEN_IP_ADDRESS, &service.sin_addr) <= 0) {
        fprintf(stderr, "inet_pton failed for IP %s\n", LISTEN_IP_ADDRESS);
        closesocket(g_ListenSocket); return 1;
    }
    service.sin_port = htons((USHORT)atoi(SERVER_PORT));
    if (bind(g_ListenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        fprintf(stderr, "bind failed: %d\n", WSAGetLastError());
        closesocket(g_ListenSocket); return 1;
    }

    // Listen
    if (listen(g_ListenSocket, SOMAXCONN) == SOCKET_ERROR) { //USE GLOBAL
        fprintf(stderr, "listen failed: %d\n", WSAGetLastError());
        closesocket(g_ListenSocket); return 1;
    }

    // Associate listening socket with IOCP using a specific key
    if (CreateIoCompletionPort((HANDLE)g_ListenSocket, g_hIoCompletionPort, LISTEN_SOCKET_COMPLETION_KEY, 0) == NULL) {
        fprintf(stderr, "Failed to associate g_ListenSocket with IOCP: %d\n", GetLastError());
        closesocket(g_ListenSocket);
        // Proper cleanup of already initialized parts (IOCP, g_hServerCreds)
        if (g_hIoCompletionPort) CloseHandle(g_hIoCompletionPort);
        if (g_hServerCreds.dwLower || g_hServerCreds.dwUpper) FreeCredentialsHandle(&g_hServerCreds);
        WSACleanup();
        return 1;
    }

    printf("Server listening on %s:%s g_ListenSocket associated with IOCP...\n", LISTEN_IP_ADDRESS, SERVER_PORT);

    //**********************************************

    // Load AcceptEx (using g_ListenSocket)
    GUID GuidAcceptEx = WSAID_ACCEPTEX;
    DWORD dwBytes;
    if (WSAIoctl(g_ListenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &GuidAcceptEx, sizeof(GuidAcceptEx),
        &g_lpfnAcceptEx, sizeof(g_lpfnAcceptEx),
        &dwBytes, NULL, NULL) == SOCKET_ERROR) {
        fprintf(stderr, "WSAIoctl(AcceptEx) failed: %d\n", WSAGetLastError());
        closesocket(g_ListenSocket); return 1;
    }

    // Create initial AcceptEx operations (e.g., a few to start)
    printf("Posting initial AcceptEx calls...\n"); // ADDED for clarity
    for (int i = 0; i < 5; i++) {
        PPER_IO_CONTEXT pAcceptIoContext = (PPER_IO_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PER_IO_CONTEXT));
        if (!pAcceptIoContext) { 
            fprintf(stderr, "Failed to alloc pAcceptIoContext\n");
            break; 
        } // Should handle error better
        
        // PostAccept no longer takes ListenSocket as it uses the global g_ListenSocket
        if (!PostAccept(pAcceptIoContext)) {
            HeapFree(GetProcessHeap(), 0, pAcceptIoContext);
            //HeapFree(pAcceptIoContext);
            fprintf(stderr, "Initial PostAccept failed in main loop. Server might not be fully operational.\n");
            // Decide if this is fatal or if you try to continue
            // Handle error, maybe means server can't start
        }
        // If PostAccept is successful, pAcceptIoContext is now owned by the system
    }

    printf("Server setup complete. Waiting for connections...\n");
    // Server runs until g_bServerRunning is false (e.g., on console input)
    // For this example, we'll just sleep or wait for a key press.
    // In a real server, this thread might do other work or just monitor.
    while (g_bServerRunning) {
        Sleep(1000); // Main thread can do other things or just wait
        // Add a way to signal g_bServerRunning = FALSE to shutdown
    }

    // TODO: Proper shutdown: signal worker threads, close IOCP, cleanup all contexts
    printf("Server setup complete. Waiting for connections...\n");
    //CloseHandle(g_hIoCompletionPort);

    if (g_ListenSocket != INVALID_SOCKET) {
        closesocket(g_ListenSocket);
        g_ListenSocket = INVALID_SOCKET;
    }
    //closesocket(g_ListenSocket);
    if (g_hServerCreds.dwLower != 0 || g_hServerCreds.dwUpper != 0) {
        FreeCredentialsHandle(&g_hServerCreds);
    }
    WSACleanup();
    return 0;
}

// --- Initialization Functions ---
BOOL InitializeWinsock() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", WSAGetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL InitializeIOCP() {
    g_hIoCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (g_hIoCompletionPort == NULL) {
        fprintf(stderr, "CreateIoCompletionPort failed: %d\n", GetLastError());
        return FALSE;
    }

    SYSTEM_INFO SystemInfo;
    GetSystemInfo(&SystemInfo);
    for (DWORD i = 0; i < DEFAULT_WORKER_THREAD_COUNT; i++) {
        HANDLE hThread = CreateThread(NULL, 0, WorkerThread, g_hIoCompletionPort, 0, NULL);
        if (hThread == NULL) {
            fprintf(stderr, "CreateThread for worker failed: %d\n", GetLastError());
            // Handle error, possibly by trying to continue with fewer threads or failing startup
        }
        else {
            CloseHandle(hThread); // We don't need to manage these thread handles directly
        }
    }
    return TRUE;
}

BOOL InitializeSchannel() {
    PCCERT_CONTEXT pServerCert = FindServerCertificateByName(CERT_SUBJECT_NAME_A);
    if (!pServerCert) {
        fprintf(stderr, "InitializeSchannel: Server certificate '%s' not found.\n", CERT_SUBJECT_NAME_A);
        return FALSE;
    }
    printf("InitializeSchannel: Server certificate found.\n");

    if (AcquireServerCredentialsSCH(pServerCert, &g_hServerCreds) != SEC_E_OK) {
        CertFreeCertificateContext(pServerCert);
        fprintf(stderr, "InitializeSchannel: AcquireServerCredentialsSCH failed.\n");
        return FALSE;
    }
    CertFreeCertificateContext(pServerCert);
    printf("InitializeSchannel: Server credentials acquired successfully.\n");
    return TRUE;
}

PCCERT_CONTEXT FindServerCertificateByName(LPCSTR pszSubjectNameA) { // Changed to ANSI
    HCERTSTORE hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, (HCRYPTPROV_LEGACY)NULL,
        CERT_SYSTEM_STORE_LOCAL_MACHINE, "MY");
    if (!hMyCertStore) {
        fprintf(stderr, "FindServerCertificateByName: CertOpenStore failed: 0x%lx\n", GetLastError());
        return NULL;
    }
    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(hMyCertStore, X509_ASN_ENCODING, 0,
        CERT_FIND_SUBJECT_STR_A, pszSubjectNameA, NULL);
    if (!pCertContext) {
        fprintf(stderr, "FindServerCertificateByName: CertFindCertificateInStore failed for '%s': 0x%lx\n",
            pszSubjectNameA, GetLastError());
    }
    CertCloseStore(hMyCertStore, 0);
    return pCertContext;
}

SECURITY_STATUS AcquireServerCredentialsSCH(PCCERT_CONTEXT pCertContext, CredHandle* phCreds) {
    SCH_CREDENTIALS SchannelCred = { 0 };
    TimeStamp tsExpiry;
    SchannelCred.dwVersion = SCH_CREDENTIALS_VERSION;
    SchannelCred.dwCredFormat = SCH_CRED_FORMAT_CERT_CONTEXT;
    SchannelCred.cCreds = 1;
    SchannelCred.paCred = &pCertContext;
    //SchannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
   SchannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;

    // No grbitEnabledProtocols - relies on OS defaults (TLS 1.2/1.3 if enabled in registry)

    SECURITY_STATUS Status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, // Use ANSI version
        SECPKG_CRED_INBOUND, NULL, &SchannelCred,
        NULL, NULL, phCreds, &tsExpiry);
    if (Status != SEC_E_OK) {
        fprintf(stderr, "AcquireServerCredentialsSCH: AcquireCredentialsHandle failed: 0x%lx\n", Status);
    }
    return Status;
}


// --- IOCP Helper Functions ---
// PostAccept now uses the global g_ListenSocket, and pAcceptIoContext is pre-allocated by caller
BOOL PostAccept(PPER_IO_CONTEXT pAcceptIoContext) { // ListenSocket parameter removed
    assert(g_lpfnAcceptEx != NULL);
    assert(g_ListenSocket != INVALID_SOCKET);
    assert(pAcceptIoContext != NULL); // Caller must provide allocated context

    SOCKET client_socket_for_this_accept = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (client_socket_for_this_accept == INVALID_SOCKET) {
        fprintf(stderr, "PostAccept: WSASocket(client_socket) failed: %d\n", WSAGetLastError());
        return FALSE; // The caller (main loop or HandleAcceptCompletion) will free pAcceptIoContext
    }

    pAcceptIoContext->OperationType = IO_ACCEPT;
    pAcceptIoContext->AcceptSocket = client_socket_for_this_accept; // Store the new socket
    pAcceptIoContext->pSocketContext = NULL; // This PER_IO_CONTEXT is not yet tied to a full PER_SOCKET_CONTEXT

    // CRITICAL: Zero out the OVERLAPPED structure before each overlapped call.
    // This ensures hEvent is NULL, which is correct for IOCP completions.
    ZeroMemory(&pAcceptIoContext->Overlapped, sizeof(OVERLAPPED));

    DWORD dwBytesReceivedDummy = 0; // For AcceptEx, this will be 0 if dwReceiveDataLength is 0

    printf("Server: Posting AcceptEx on ListenSocket %llu with new AcceptSocket %llu using PER_IO_CONTEXT %p\n",
        (UINT_PTR)g_ListenSocket, (UINT_PTR)pAcceptIoContext->AcceptSocket, (void*)pAcceptIoContext);

    BOOL result = g_lpfnAcceptEx(
        g_ListenSocket,                 // Use global listening socket
        pAcceptIoContext->AcceptSocket, // The pre-created socket for the new connection
        pAcceptIoContext->Buffer,       // Buffer for local/remote addresses
        0,                              // dwReceiveDataLength - receive 0 bytes of initial data with accept
        sizeof(SOCKADDR_IN) + 16,       // dwLocalAddressLength
        sizeof(SOCKADDR_IN) + 16,       // dwRemoteAddressLength
        &dwBytesReceivedDummy,
        &pAcceptIoContext->Overlapped
    );

    if (!result) {
        int lastError = WSAGetLastError();
        if (lastError != WSA_IO_PENDING) {
            fprintf(stderr, "PostAccept: AcceptEx call failed with error: %d\n", lastError);
            closesocket(pAcceptIoContext->AcceptSocket); // Clean up the socket we created
            pAcceptIoContext->AcceptSocket = INVALID_SOCKET;
            return FALSE; // The caller (main loop or HandleAcceptCompletion) will free pAcceptIoContext
        }
    }
    // If AcceptEx returns TRUE or (FALSE with WSA_IO_PENDING), the operation is successfully queued.
    printf("Server: AcceptEx successfully posted for PER_IO_CONTEXT %p.\n", (void*)pAcceptIoContext);
    return TRUE;
}


BOOL PostRecv(PPER_SOCKET_CONTEXT pSocketContext) {
    ZeroMemory(&pSocketContext->ReadIoContext.Overlapped, sizeof(OVERLAPPED));
    pSocketContext->ReadIoContext.pSocketContext = pSocketContext; // Link back
    pSocketContext->ReadIoContext.WSABuf.buf = pSocketContext->ReadIoContext.Buffer;
    pSocketContext->ReadIoContext.WSABuf.len = sizeof(pSocketContext->ReadIoContext.Buffer);
    pSocketContext->ReadIoContext.OperationType = pSocketContext->HandshakeComplete ? IO_READ_ENCRYPTED_APP : IO_READ_HANDSHAKE;

    DWORD dwFlags = 0;
    DWORD dwRecvBytes = 0;
    if (WSARecv(pSocketContext->Socket, &pSocketContext->ReadIoContext.WSABuf, 1, &dwRecvBytes, &dwFlags,
        &pSocketContext->ReadIoContext.Overlapped, NULL) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            fprintf(stderr, "PostRecv: WSARecv failed for socket %llu: %d\n", (UINT_PTR)pSocketContext->Socket, WSAGetLastError());
            CloseClientConnection(pSocketContext, FALSE);
            return FALSE;
        }
    }
    printf("Server: Posted WSARecv for socket %llu, op %d\n", (UINT_PTR)pSocketContext->Socket, pSocketContext->ReadIoContext.OperationType);
    return TRUE;
}

BOOL PostSend(PPER_SOCKET_CONTEXT pSocketContext, PBYTE pbData, DWORD cbData, IO_OPERATION opType) {
    if (cbData == 0) return TRUE; // Nothing to send
    if (cbData > sizeof(pSocketContext->WriteIoContext.Buffer)) {
        fprintf(stderr, "PostSend: Data too large for WriteIoContext.Buffer (%lu vs %u)\n", cbData, (unsigned int)sizeof(pSocketContext->WriteIoContext.Buffer));
        // TODO: Implement sending large data in chunks if necessary
        CloseClientConnection(pSocketContext, FALSE); // Or handle error differently
        return FALSE;
    }

    memcpy(pSocketContext->WriteIoContext.Buffer, pbData, cbData);
    ZeroMemory(&pSocketContext->WriteIoContext.Overlapped, sizeof(OVERLAPPED));
    pSocketContext->WriteIoContext.pSocketContext = pSocketContext; // Link back
    pSocketContext->WriteIoContext.WSABuf.buf = pSocketContext->WriteIoContext.Buffer;
    pSocketContext->WriteIoContext.WSABuf.len = cbData;
    pSocketContext->WriteIoContext.OperationType = opType;
    pSocketContext->WriteIoContext.TotalBytesToSend = cbData;
    pSocketContext->WriteIoContext.BytesSentSoFar = 0;

    DWORD dwSentBytes = 0;
    if (WSASend(pSocketContext->Socket, &pSocketContext->WriteIoContext.WSABuf, 1, &dwSentBytes, 0,
        &pSocketContext->WriteIoContext.Overlapped, NULL) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSA_IO_PENDING) {
            fprintf(stderr, "PostSend: WSASend failed for socket %llu: %d\n", (UINT_PTR)pSocketContext->Socket, WSAGetLastError());
            CloseClientConnection(pSocketContext, FALSE);
            return FALSE;
        }
    }
    printf("Server: Posted WSASend (%lu bytes) for socket %llu, op %d\n", cbData, (UINT_PTR)pSocketContext->Socket, opType);
    return TRUE;
}

// --- I/O Completion Handlers (Called by WorkerThread) ---
// HandleAcceptCompletion is called when an AcceptEx operation completes.
// pCompletedAcceptIoContext is the PER_IO_CONTEXT that was used for the specific AcceptEx call.
void HandleAcceptCompletion(PPER_IO_CONTEXT pCompletedAcceptIoContext) { // ListenSocket removed from params, uses g_ListenSocket
    SOCKET AcceptedSocket = pCompletedAcceptIoContext->AcceptSocket; // Get the socket from our context member

    if (AcceptedSocket == INVALID_SOCKET) { // Should have been caught by bSuccess in WorkerThread
        fprintf(stderr, "HandleAcceptCompletion: Invalid AcceptedSocket in PER_IO_CONTEXT.\n");
        // This PER_IO_CONTEXT is now effectively dead for this accept attempt.
        // We should try to post a new accept with it to keep the pool going.
        // Or, if it's truly bad, free pCompletedAcceptIoContext and post a brand new one.
        // For now, let's try to re-post it.
        if (!PostAccept(pCompletedAcceptIoContext)) {
            // If re-posting fails, we have one less pending accept.
        // The pCompletedAcceptIoContext should be freed as it's no longer in use.
            fprintf(stderr, "HandleAcceptCompletion: Failed to re-post AcceptEx with PER_IO_CONTEXT %p. Freeing it.\n", (void*)pCompletedAcceptIoContext);
            if (pCompletedAcceptIoContext->AcceptSocket != INVALID_SOCKET) { // Check if socket was created
                closesocket(pCompletedAcceptIoContext->AcceptSocket);
            }
            HeapFree(GetProcessHeap(), 0, pCompletedAcceptIoContext);
        }
        else {
            printf("HandleAcceptCompletion: Successfully re-posted AcceptEx with PER_IO_CONTEXT %p.\n", (void*)pCompletedAcceptIoContext);
        }
        return;
    }

    // Set socket options on the accepted socket
    if (setsockopt(AcceptedSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
        (char*)&g_ListenSocket, sizeof(g_ListenSocket)) != 0) {
        fprintf(stderr, "HandleAcceptCompletion: setsockopt SO_UPDATE_ACCEPT_CONTEXT failed: %d for socket %llu\n",
            WSAGetLastError(), (UINT_PTR)AcceptedSocket);
        // This is not necessarily fatal, but can affect getpeername/getsockname immediately
    }

    // Create and initialize PER_SOCKET_CONTEXT for the new connection
    PPER_SOCKET_CONTEXT pNewSocketContext = (PPER_SOCKET_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PER_SOCKET_CONTEXT));
    if (!pNewSocketContext) {
        fprintf(stderr, "HandleAcceptCompletion: Failed to allocate PER_SOCKET_CONTEXT for socket %llu.\n", (UINT_PTR)AcceptedSocket);
        closesocket(AcceptedSocket);
        // Re-post the original pCompletedAcceptIoContext for the next client
        if (!PostAccept(pCompletedAcceptIoContext)) {
            HeapFree(GetProcessHeap(), 0, pCompletedAcceptIoContext);
        }
        return;
    }

    pNewSocketContext->Socket = AcceptedSocket;
    pNewSocketContext->pServerCredsHandle = &g_hServerCreds;
    pNewSocketContext->HandshakeInProgress = TRUE;
    pNewSocketContext->HandshakeComplete = FALSE;
    pNewSocketContext->bFirstSchannelCall = TRUE;
    pNewSocketContext->SchannelContextInitialized = FALSE;
    pNewSocketContext->cbSchannelAccumulatedRecvBuffer = 0;

    // Initialize embedded PER_IO_CONTEXTs within PER_SOCKET_CONTEXT
    pNewSocketContext->ReadIoContext.pSocketContext = pNewSocketContext; // Link back
    pNewSocketContext->WriteIoContext.pSocketContext = pNewSocketContext; // Link back

    // Associate the new client socket with the IOCP.
    // The completion key for future I/O on this AcceptedSocket will be pNewSocketContext.
    if (CreateIoCompletionPort((HANDLE)pNewSocketContext->Socket, g_hIoCompletionPort, (ULONG_PTR)pNewSocketContext, 0) == NULL) {
        fprintf(stderr, "HandleAcceptCompletion: CreateIoCompletionPort for client socket %llu failed: %d\n",
            (UINT_PTR)pNewSocketContext->Socket, GetLastError());
        closesocket(pNewSocketContext->Socket);
        HeapFree(GetProcessHeap(), 0, pNewSocketContext);
        // Re-post the original pCompletedAcceptIoContext for the next client
        if (!PostAccept(pCompletedAcceptIoContext)) {
            HeapFree(GetProcessHeap(), 0, pCompletedAcceptIoContext);
        }
        return;
    }

    printf("Server: Client connected (socket %llu). Associated with IOCP. Posting initial Schannel read.\n", (UINT_PTR)pNewSocketContext->Socket);

    // Post an initial read on the new connection to receive the client's first handshake token
    if (!PostRecv(pNewSocketContext)) {
        // PostRecv would have called CloseClientConnection which frees pNewSocketContext
        // CloseClientConnection also frees the embedded ReadIoContext/WriteIoContext.
        printf("HandleAcceptCompletion: Initial PostRecv failed for new client %llu.\n", (UINT_PTR)pNewSocketContext->Socket);
        // pNewSocketContext is already freed by CloseClientConnection.
    }

    // Re-post the AcceptEx operation using the *same* pCompletedAcceptIoContext structure
    // to accept the next incoming connection. This recycles the PER_IO_CONTEXT for accepts.
    if (!PostAccept(pCompletedAcceptIoContext)) {
        // If re-posting fails, we have one less pending accept.
        // The pCompletedAcceptIoContext should be freed as it's no longer in use by an overlapped operation
        // and won't be re-used by another PostAccept call.
        fprintf(stderr, "HandleAcceptCompletion: Failed to re-post AcceptEx with PER_IO_CONTEXT %p. Freeing it.\n", (void*)pCompletedAcceptIoContext);
        closesocket(pCompletedAcceptIoContext->AcceptSocket); // Close the socket it might have created if PostAccept failed internally
        HeapFree(GetProcessHeap(), 0, pCompletedAcceptIoContext);
    }
    else {
        printf("HandleAcceptCompletion: Successfully re-posted AcceptEx with PER_IO_CONTEXT %p.\n", (void*)pCompletedAcceptIoContext);
    }
}


void HandleReadCompletion(PPER_SOCKET_CONTEXT pSocketContext, DWORD dwBytesTransferred) {
    if (!pSocketContext || dwBytesTransferred == 0) { // dwBytesTransferred == 0 means graceful close by peer
        printf("Server: HandleReadCompletion - Connection closed or error for socket %llu.\n", pSocketContext ? (UINT_PTR)pSocketContext->Socket : 0);
        CloseClientConnection(pSocketContext, FALSE);
        return;
    }

    // Append received data to the socket's accumulation buffer
    if (pSocketContext->cbSchannelAccumulatedRecvBuffer + dwBytesTransferred > MAX_SCHANNEL_RECV_BUFFER_SIZE) {
        fprintf(stderr, "Server: Schannel receive buffer overflow for socket %llu.\n", (UINT_PTR)pSocketContext->Socket);
        CloseClientConnection(pSocketContext, FALSE);
        return;
    }
    memcpy(pSocketContext->SchannelAccumulatedRecvBuffer + pSocketContext->cbSchannelAccumulatedRecvBuffer,
        pSocketContext->ReadIoContext.Buffer, // Data is in the ReadIoContext's buffer
        dwBytesTransferred);
    pSocketContext->cbSchannelAccumulatedRecvBuffer += dwBytesTransferred;

    printf("Server: HandleReadCompletion: Received %lu bytes for socket %llu. Total buffered: %lu.\n",
        dwBytesTransferred, (UINT_PTR)pSocketContext->Socket, pSocketContext->cbSchannelAccumulatedRecvBuffer);

    if (!pSocketContext->HandshakeComplete) {
        ProcessSchannelHandshake(pSocketContext);
    }
    else {
        ProcessEncryptedAppData(pSocketContext, pSocketContext->cbSchannelAccumulatedRecvBuffer);
    }
}

void ProcessSchannelHandshake(PPER_SOCKET_CONTEXT pSocketContext) {
    SECURITY_STATUS SecStatus;
    SecBufferDesc OutBufferDesc;
    SecBuffer OutBuffers[1];
    SecBufferDesc InBufferDesc;
    SecBuffer InBuffers[2]; // Input for ASC
    DWORD dwSSPIFlags, dwSSPIOutFlags;
    TimeStamp tsExpiry;

    if (!pSocketContext->HandshakeInProgress) return; // Should not happen if called correctly

    printf("Server: ProcessSchannelHandshake for socket %llu. Buffered data: %lu bytes.\n",
        (UINT_PTR)pSocketContext->Socket, pSocketContext->cbSchannelAccumulatedRecvBuffer);

    dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
        ASC_REQ_EXTENDED_ERROR | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;

    OutBufferDesc.ulVersion = SECBUFFER_VERSION;
    OutBufferDesc.cBuffers = 1;
    OutBufferDesc.pBuffers = OutBuffers;
    OutBuffers[0].pvBuffer = NULL;
    OutBuffers[0].cbBuffer = 0;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;

    InBufferDesc.ulVersion = SECBUFFER_VERSION;
    InBufferDesc.cBuffers = 2;
    InBufferDesc.pBuffers = InBuffers;
    InBuffers[0].pvBuffer = pSocketContext->SchannelAccumulatedRecvBuffer;
    InBuffers[0].cbBuffer = pSocketContext->cbSchannelAccumulatedRecvBuffer;
    InBuffers[0].BufferType = SECBUFFER_TOKEN;
    InBuffers[1].pvBuffer = NULL; // For SECBUFFER_EXTRA
    InBuffers[1].cbBuffer = 0;
    InBuffers[1].BufferType = SECBUFFER_EMPTY;

    SecStatus = AcceptSecurityContext(
        pSocketContext->pServerCredsHandle,
        pSocketContext->bFirstSchannelCall ? NULL : &pSocketContext->SchannelContext,
        &InBufferDesc, dwSSPIFlags, SECURITY_NATIVE_DREP,
        pSocketContext->bFirstSchannelCall ? &pSocketContext->SchannelContext : NULL,
        &OutBufferDesc, &dwSSPIOutFlags, &tsExpiry);

    if (pSocketContext->bFirstSchannelCall &&
        (SecStatus == SEC_E_OK || SecStatus == SEC_I_CONTINUE_NEEDED || SecStatus == SEC_I_INCOMPLETE_CREDENTIALS)) {
        pSocketContext->SchannelContextInitialized = TRUE;
    }
    pSocketContext->bFirstSchannelCall = FALSE;

    printf("Server: AcceptSecurityContext returned 0x%lx for socket %llu.\n", SecStatus, (UINT_PTR)pSocketContext->Socket);

    // --- Send output token to client (if any) ---
    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL) {
        // This PostSend will queue an IO_WRITE_HANDSHAKE operation.
        // The completion of this send will be handled in HandleWriteCompletion.
        PostSend(pSocketContext, (PBYTE)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, IO_WRITE_HANDSHAKE);
        FreeContextBuffer(OutBuffers[0].pvBuffer); // Free token buffer after PostSend copies it
    }

    // --- Manage leftover input data and decide next step ---
    DWORD leftoverDataSize = 0;
    PBYTE leftoverDataStart = NULL;

    if (InBuffers[1].BufferType == SECBUFFER_EXTRA && InBuffers[1].cbBuffer > 0) {
        leftoverDataStart = (PBYTE)InBuffers[1].pvBuffer;
        leftoverDataSize = InBuffers[1].cbBuffer;
    }
    else if (InBuffers[0].BufferType == SECBUFFER_TOKEN && InBuffers[0].cbBuffer > 0) {
        // If ASC didn't consume all of InBuffers[0] and didn't put extra in InBuffers[1]
        leftoverDataStart = (PBYTE)InBuffers[0].pvBuffer;
        leftoverDataSize = InBuffers[0].cbBuffer;
    }

    if (leftoverDataSize > 0 && leftoverDataStart) {
        printf("Server: ASC consumed some, %lu bytes leftover in SChannelRecvBuffer.\n", leftoverDataSize);
        if (leftoverDataStart != pSocketContext->SchannelAccumulatedRecvBuffer) { // Schannel might advance pointer
            MoveMemory(pSocketContext->SchannelAccumulatedRecvBuffer, leftoverDataStart, leftoverDataSize);
        }
        pSocketContext->cbSchannelAccumulatedRecvBuffer = leftoverDataSize;
    }
    else {
        pSocketContext->cbSchannelAccumulatedRecvBuffer = 0; // All consumed
    }

    // --- Decide next action based on SecStatus ---
    if (SecStatus == SEC_E_OK) {
        pSocketContext->HandshakeInProgress = FALSE;
        pSocketContext->HandshakeComplete = TRUE;
        QueryAndPrintProtocol(&pSocketContext->SchannelContext, TRUE);
        QueryContextAttributes(&pSocketContext->SchannelContext, SECPKG_ATTR_STREAM_SIZES, &pSocketContext->StreamSizes);
        printf("Server: Handshake complete for socket %llu. Stream header: %lu, trailer: %lu, max_msg: %lu\n",
            (UINT_PTR)pSocketContext->Socket, pSocketContext->StreamSizes.cbHeader,
            pSocketContext->StreamSizes.cbTrailer, pSocketContext->StreamSizes.cbMaximumMessage);

        // If there's leftover data, it might be early app data. Try to process it.
        if (pSocketContext->cbSchannelAccumulatedRecvBuffer > 0) {
            printf("Server: Early app data (%lu bytes) after handshake. Processing.\n", pSocketContext->cbSchannelAccumulatedRecvBuffer);
            ProcessEncryptedAppData(pSocketContext, pSocketContext->cbSchannelAccumulatedRecvBuffer);
        }
        else {
            // No leftover data, post a read for application data
            PostRecv(pSocketContext);
        }
    }
    else if (SecStatus == SEC_I_CONTINUE_NEEDED || SecStatus == SEC_I_INCOMPLETE_CREDENTIALS) {
        // If we sent an output token (OutBuffers[0].cbBuffer > 0),
        // the next step (reading from client) will be triggered by the HandleWriteCompletion.
        // If we did NOT send an output token, we need more data from the client immediately.
        if (OutBuffers[0].cbBuffer == 0) {
            if (pSocketContext->cbSchannelAccumulatedRecvBuffer > 0) {
                // There's leftover data, try to process it again in the next Schannel iteration.
                // This can happen if a full TLS record contained multiple handshake messages
                // or if ASC needs to be called again on the same (now marked leftover) data.
                // This state implies we should re-post an internal "process buffered data" event.
                // For simplicity here, if we have data, try to process it. This could loop if ASC doesn't consume.
                // A safer way is to post a new read if ASC consistently returns CONTINUE_NEEDED on same data without INCOMPLETE.
                printf("Server: ASC CONTINUE_NEEDED, no token sent, data buffered (%lu). Re-posting read for safety.\n", pSocketContext->cbSchannelAccumulatedRecvBuffer);
                PostRecv(pSocketContext); // Re-post read, new data will append. Or process existing again.

            }
            else {
                PostRecv(pSocketContext); // Need more data from client
            }
        }
        // If a token was sent, HandleWriteCompletion will call PostRecv.
    }
    else if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
        // Not enough data in SChannelRecvBuffer for a full token. Post another read.
        // cbSchannelAccumulatedRecvBuffer already holds the partial data.
        printf("Server: ASC SEC_E_INCOMPLETE_MESSAGE. Buffered: %lu. Posting read for more.\n", pSocketContext->cbSchannelAccumulatedRecvBuffer);
        PostRecv(pSocketContext);
    }
    else {
        // Handshake failed
        fprintf(stderr, "Server: Schannel handshake processing failed: 0x%lx for socket %llu\n", SecStatus, (UINT_PTR)pSocketContext->Socket);
        CloseClientConnection(pSocketContext, FALSE);
    }
}


void HandleWriteCompletion(PPER_SOCKET_CONTEXT pSocketContext, PPER_IO_CONTEXT pIoWriteContext, DWORD dwBytesTransferred) {
    if (!pSocketContext) return;

    pIoWriteContext->BytesSentSoFar += dwBytesTransferred;
    printf("Server: HandleWriteCompletion: Sent %lu bytes for socket %llu. Total so far: %lu / %lu.\n",
        dwBytesTransferred, (UINT_PTR)pSocketContext->Socket, pIoWriteContext->BytesSentSoFar, pIoWriteContext->TotalBytesToSend);

    if (pIoWriteContext->BytesSentSoFar < pIoWriteContext->TotalBytesToSend) {
        // Not all data was sent, post another WSASend for the remainder
        pIoWriteContext->WSABuf.buf = pIoWriteContext->Buffer + pIoWriteContext->BytesSentSoFar;
        pIoWriteContext->WSABuf.len = pIoWriteContext->TotalBytesToSend - pIoWriteContext->BytesSentSoFar;
        ZeroMemory(&pIoWriteContext->Overlapped, sizeof(OVERLAPPED)); // Must re-zero for re-post

        if (WSASend(pSocketContext->Socket, &pIoWriteContext->WSABuf, 1, NULL, 0,
            &pIoWriteContext->Overlapped, NULL) == SOCKET_ERROR) {
            if (WSAGetLastError() != WSA_IO_PENDING) {
                fprintf(stderr, "HandleWriteCompletion: WSASend (cont) failed for socket %llu: %d\n", (UINT_PTR)pSocketContext->Socket, WSAGetLastError());
                CloseClientConnection(pSocketContext, FALSE);
                // No need to free pIoWriteContext if it's embedded in pSocketContext
            }
        }
    }
    else {
        // All data for this send operation has been sent successfully
        printf("Server: Full send complete for op %d on socket %llu.\n", pIoWriteContext->OperationType, (UINT_PTR)pSocketContext->Socket);

        if (pIoWriteContext->OperationType == IO_WRITE_HANDSHAKE) {
            if (pSocketContext->HandshakeInProgress && !pSocketContext->HandshakeComplete) {
                // We just sent a handshake token. Now we need to read the client's response.
                printf("Server: Handshake token sent. Posting read for client's next token.\n");
                // Ensure accumulated buffer is clear if we expect a completely new token
                // pSocketContext->cbSchannelAccumulatedRecvBuffer = 0; // This should be handled by ProcessSchannelHandshake logic already
                PostRecv(pSocketContext);
            }
            else if (pSocketContext->HandshakeComplete) {
                // This might be a final handshake token (e.g. NewSessionTicket) after SEC_E_OK from ASC.
                // Application data phase can now proceed. Typically, a read would be pending for app data.
                printf("Server: Final handshake write complete. Handshake is fully done. Awaiting app data (read should be pending).\n");
                // Ensure a read is pending if not already done after SEC_E_OK
                // if(no_read_is_pending_for_app_data) PostRecv(pSocketContext);
            }
        }
        else if (pIoWriteContext->OperationType == IO_WRITE_ENCRYPTED_APP) {
            // Application data sent. Can post another read for more responses or further actions.
            // For an echo server, you might post a read after sending.
            // PostRecv(pSocketContext);
            printf("Server: Encrypted app data sent for socket %llu.\n", (UINT_PTR)pSocketContext->Socket);
        }
        // If PER_IO_CONTEXT was dynamically allocated for this write, it would be freed here.
        // Since it's embedded in PER_SOCKET_CONTEXT, we just mark it as "done" implicitly.
    }
}

void ProcessEncryptedAppData(PPER_SOCKET_CONTEXT pSocketContext, DWORD dwDataLenInAccumulationBuffer) {
    printf("Server: ProcessEncryptedAppData called for socket %llu with %lu bytes.\n", (UINT_PTR)pSocketContext->Socket, dwDataLenInAccumulationBuffer);
    // This is where you'd call DecryptMessage in a loop if dwDataLenInAccumulationBuffer > 0
    // For now, let's just conceptualize an echo

    SecBuffer Buffers[4];
    SecBufferDesc MessageDesc;
    SECURITY_STATUS SecStatus;
    ULONG ulQop;

    // Loop to decrypt all messages in the buffer
    while (pSocketContext->cbSchannelAccumulatedRecvBuffer > 0) {
        Buffers[0].pvBuffer = pSocketContext->SchannelAccumulatedRecvBuffer;
        Buffers[0].cbBuffer = pSocketContext->cbSchannelAccumulatedRecvBuffer;
        Buffers[0].BufferType = SECBUFFER_DATA;

        Buffers[1].BufferType = SECBUFFER_EMPTY; Buffers[1].cbBuffer = 0; Buffers[1].pvBuffer = NULL;
        Buffers[2].BufferType = SECBUFFER_EMPTY; Buffers[2].cbBuffer = 0; Buffers[2].pvBuffer = NULL;
        Buffers[3].BufferType = SECBUFFER_EMPTY; Buffers[3].cbBuffer = 0; Buffers[3].pvBuffer = NULL;

        MessageDesc.ulVersion = SECBUFFER_VERSION;
        MessageDesc.cBuffers = 4;
        MessageDesc.pBuffers = Buffers;

        SecStatus = DecryptMessage(&pSocketContext->SchannelContext, &MessageDesc, 0, &ulQop);

        if (SecStatus == SEC_E_OK) {
            PBYTE pDecryptedBuffer = NULL;
            DWORD cbDecryptedBuffer = 0;
            PBYTE pExtraData = NULL;
            DWORD cbExtraData = 0;

            for (int i = 0; i < 4; i++) {
                if (Buffers[i].BufferType == SECBUFFER_DATA) {
                    pDecryptedBuffer = (PBYTE)Buffers[i].pvBuffer;
                    cbDecryptedBuffer = Buffers[i].cbBuffer;
                }
                else if (Buffers[i].BufferType == SECBUFFER_EXTRA && Buffers[i].cbBuffer > 0) {
                    pExtraData = (PBYTE)Buffers[i].pvBuffer;
                    cbExtraData = Buffers[i].cbBuffer;
                }
            }

            if (pDecryptedBuffer && cbDecryptedBuffer > 0) {
                printf("Server: Decrypted %lu bytes: %.*s\n", cbDecryptedBuffer, cbDecryptedBuffer, (char*)pDecryptedBuffer);
                // TODO: Echo back - Call EncryptMessage then PostSend
                // For now, just print.
            }

            if (cbExtraData > 0 && pExtraData) {
                printf("Server: DecryptMessage SECBUFFER_EXTRA %lu bytes.\n", cbExtraData);
                MoveMemory(pSocketContext->SchannelAccumulatedRecvBuffer, pExtraData, cbExtraData);
                pSocketContext->cbSchannelAccumulatedRecvBuffer = cbExtraData;
            }
            else {
                pSocketContext->cbSchannelAccumulatedRecvBuffer = 0; // All processed
            }
        }
        else if (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
            printf("Server: DecryptMessage needs more data (SEC_E_INCOMPLETE_MESSAGE). Buffered: %lu.\n", pSocketContext->cbSchannelAccumulatedRecvBuffer);
            PostRecv(pSocketContext); // Post read to get more data
            return; // Exit, wait for more data
        }
        else if (SecStatus == SEC_I_CONTEXT_EXPIRED) {
            printf("Server: DecryptMessage: context expired (client initiated shutdown).\n");
            CloseClientConnection(pSocketContext, TRUE); // True for graceful Schannel aware shutdown
            return;
        }
        else if (SecStatus == SEC_I_RENEGOTIATE) {
            printf("Server: DecryptMessage: SEC_I_RENEGOTIATE. Restarting handshake.\n");
            pSocketContext->HandshakeInProgress = TRUE;
            pSocketContext->HandshakeComplete = FALSE;
            pSocketContext->bFirstSchannelCall = TRUE; // Reset for re-handshake
            // Pass the renegotiation token (usually in Buffers[1] from DecryptMessage output)
            // back into AcceptSecurityContext. This is complex.
            // For now, just re-initiate handshake process by calling ProcessSchannelHandshake.
            // The SChannelRecvBuffer might contain the token for renegotiation.
            ProcessSchannelHandshake(pSocketContext);
            return;
        }
        else {
            fprintf(stderr, "Server: DecryptMessage failed: 0x%lx for socket %llu\n", SecStatus, (UINT_PTR)pSocketContext->Socket);
            CloseClientConnection(pSocketContext, FALSE);
            return;
        }
        if (pSocketContext->cbSchannelAccumulatedRecvBuffer == 0) break; // No more data in buffer
    } // end while

    // If all processed, post another read
    if (pSocketContext->cbSchannelAccumulatedRecvBuffer == 0) {
        PostRecv(pSocketContext);
    }
}


void CloseClientConnection(PPER_SOCKET_CONTEXT pSocketContext, BOOL bGracefulSchannelShutdown) {
    if (!pSocketContext) return;

    printf("Server: Closing connection for socket %llu.\n", (UINT_PTR)pSocketContext->Socket);

    if (bGracefulSchannelShutdown && pSocketContext->SchannelContextInitialized && pSocketContext->HandshakeComplete) {
        // TODO: Implement Schannel graceful shutdown (ApplyControlToken, send token, wait for reply)
        // This would also be an asynchronous operation sequence.
        // For now, we'll just delete context.
        printf("Server: (TODO: Implement Schannel graceful shutdown here for socket %llu).\n", (UINT_PTR)pSocketContext->Socket);
    }

    if (pSocketContext->SchannelContextInitialized) {
        DeleteSecurityContext(&pSocketContext->SchannelContext);
        pSocketContext->SchannelContextInitialized = FALSE;
    }
    if (pSocketContext->Socket != INVALID_SOCKET) {
        // It's good practice to shutdown before closesocket, especially with IOCP
        // as there might be pending operations. CancelIoEx might be needed for robust shutdown.
        shutdown(pSocketContext->Socket, SD_BOTH);
        closesocket(pSocketContext->Socket);
        pSocketContext->Socket = INVALID_SOCKET;
    }
    HeapFree(GetProcessHeap(), 0, pSocketContext);
}


// --- Worker Thread ---
DWORD WINAPI WorkerThread(LPVOID lpParamIOCP) {
    HANDLE hIoCompletionPort = (HANDLE)lpParamIOCP;
    DWORD dwBytesTransferred;
    ULONG_PTR completionKey;
    PPER_SOCKET_CONTEXT pSocketContext; // This is our completion key for socket I/Os
    PPER_IO_CONTEXT pIoContext;

    printf("Worker thread %lu started.\n", GetCurrentThreadId());

    while (g_bServerRunning) {
        BOOL bSuccess = GetQueuedCompletionStatus(
            hIoCompletionPort,
            &dwBytesTransferred,
            &completionKey,                 // This is PULONG_PTR
            //(PULONG_PTR)&pSocketContext, // Key associated with the socket handle
            (LPOVERLAPPED*)&pIoContext,  // The PER_IO_CONTEXT structure used for the I/O call
            INFINITE
        );

        if (!g_bServerRunning) break; // Server is shutting down

        if (!pIoContext) { // IOCP closed or critical error signaled by posting completion with NULL pIoContext
            printf("WorkerThread %lu: GetQueuedCompletionStatus returned NULL pIoContext. Exiting.\n", GetCurrentThreadId());
            break;
        }
        // --- NEW DISPATCH LOGIC ---
        if (completionKey == LISTEN_SOCKET_COMPLETION_KEY) {
            // This is a completion for an AcceptEx operation.
            // pIoContext is the PER_IO_CONTEXT that was used for this AcceptEx call.
            assert(pIoContext->OperationType == IO_ACCEPT);

            if (bSuccess) { // AcceptEx itself succeeded (connection arrived)
                printf("WorkerThread %lu: IO_ACCEPT operation completed successfully via IOCP for PER_IO_CONTEXT %p.\n", GetCurrentThreadId(), (void*)pIoContext);
                HandleAcceptCompletion(pIoContext); // Pass the PER_IO_CONTEXT for the completed AcceptEx
            }
            else {
                fprintf(stderr, "WorkerThread %lu: AcceptEx operation failed with error %lu via IOCP for PER_IO_CONTEXT %p.\n", GetCurrentThreadId(), GetLastError(), (void*)pIoContext);
                closesocket(pIoContext->AcceptSocket); // Close the socket that was created but not successfully accepted
                HeapFree(GetProcessHeap(), 0, pIoContext); // Free the PER_IO_CONTEXT allocated for this specific AcceptEx

                // Optionally, post another AcceptEx to replace this failed one
                PPER_IO_CONTEXT pNewAcceptIoContext = (PPER_IO_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PER_IO_CONTEXT));
                if (pNewAcceptIoContext) {
                    if (!PostAccept(pNewAcceptIoContext)) {
                        HeapFree(GetProcessHeap(), 0, pNewAcceptIoContext);
                    }
                }
            }
            continue; // Done with this completion packet
        }
        // --- END OF NEW DISPATCH LOGIC FOR ACCEPT ---

        // If not an accept, then completionKey is the PPER_SOCKET_CONTEXT for an established client
        PPER_SOCKET_CONTEXT pClientSocketContext = (PPER_SOCKET_CONTEXT)completionKey;

        if (!bSuccess || (dwBytesTransferred == 0 /*&& pIoContext->OperationType != IO_ACCEPT - already handled*/)) {
            fprintf(stderr, "WorkerThread %lu: I/O failed or client disconnected (socket %llu, op %d, bytes %lu, success %d, error %lu).\n",
                GetCurrentThreadId(), pClientSocketContext ? (UINT_PTR)pClientSocketContext->Socket : 0,
                pIoContext->OperationType, dwBytesTransferred, bSuccess, GetLastError());
            CloseClientConnection(pClientSocketContext, FALSE);
            // pIoContext is part of pClientSocketContext (ReadIoContext/WriteIoContext),
            // so it's effectively handled when pClientSocketContext is freed by CloseClientConnection.
            continue;
        }

        // Regular I/O on an established client socket
        switch (pIoContext->OperationType) {
            // IO_ACCEPT should not be reached here anymore
        case IO_READ_HANDSHAKE:
        case IO_READ_ENCRYPTED_APP:
            assert(pIoContext == &pClientSocketContext->ReadIoContext);
            HandleReadCompletion(pClientSocketContext, dwBytesTransferred);
            break;

        case IO_WRITE_HANDSHAKE:
        case IO_WRITE_ENCRYPTED_APP:
            assert(pIoContext == &pClientSocketContext->WriteIoContext);
            HandleWriteCompletion(pClientSocketContext, pIoContext, dwBytesTransferred);
            break;

            // case IO_SHUTDOWN:
                // HandleSchannelShutdownStep(pClientSocketContext, pIoContext, dwBytesTransferred);
                // break;

        default:
            printf("WorkerThread %lu: Unknown/Unexpected IO operation type %d for client socket %llu\n",
                GetCurrentThreadId(), pIoContext->OperationType,
                pClientSocketContext ? (UINT_PTR)pClientSocketContext->Socket : 0);
            CloseClientConnection(pClientSocketContext, FALSE); // Unknown state
            break;
        }
    }
    printf("Worker thread %lu exiting.\n", GetCurrentThreadId());
    return 0;
}


void QueryAndPrintProtocol(CtxtHandle* phContext, BOOL isServer) {
    SecPkgContext_ConnectionInfo ConnectionInfo;
    SECURITY_STATUS SecStatus = QueryContextAttributes(phContext, SECPKG_ATTR_CONNECTION_INFO, &ConnectionInfo);
    if (SecStatus != SEC_E_OK) {
        fprintf(stderr, "%s: QueryContextAttributes (SECPKG_ATTR_CONNECTION_INFO) failed: 0x%lx\n", isServer ? "Server" : "Client", SecStatus);
        return;
    }
    printf("%s: Negotiated Protocol: ", isServer ? "Server" : "Client");
    switch (ConnectionInfo.dwProtocol) {
    case SP_PROT_TLS1_3_CLIENT: case SP_PROT_TLS1_3_SERVER: printf("TLS 1.3\n"); break;
    case SP_PROT_TLS1_2_CLIENT: case SP_PROT_TLS1_2_SERVER: printf("TLS 1.2\n"); break;
    default: printf("Other (0x%lx)\n", ConnectionInfo.dwProtocol); break;
    }
    printf("%s: Negotiated Cipher: 0x%lx (Alg: %u, Strength: %u bits)\n", isServer ? "Server" : "Client",
       ConnectionInfo.aiCipher, ConnectionInfo.dwCipherStrength);
}
