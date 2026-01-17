#include <windows.h>
#include <rpc.h>
#include <stdlib.h>
#include "ms-rprn_h.h"

/* MIDL memory allocation hooks used by generated stubs */
void* MIDL_user_allocate(size_t len) {
    return malloc(len);
}

void MIDL_user_free(void* ptr) {
    if (ptr) free(ptr);
}

/* STRING_HANDLE bind/unbind routines for implicit binding */
handle_t STRING_HANDLE_bind(STRING_HANDLE szString)
{
    handle_t hBinding = NULL;
    RPC_WSTR wszStringBinding = NULL;
    RPC_STATUS status;

    // Create an RPC binding string for ncacn_np (Named Pipe) protocol
    // szString is the server name (e.g., "\\APPSRV01")
    // Endpoint is \\pipe\\spoolss (the Print Spooler named pipe)
    status = RpcStringBindingComposeW(
        NULL,                           // UUID (NULL for dynamic endpoint)
        (RPC_WSTR)L"ncacn_np",          // Protocol sequence: Named Pipe
        (RPC_WSTR)szString,             // Network address: server name
        (RPC_WSTR)L"\\pipe\\spoolss",   // Endpoint: spoolss pipe
        NULL,                           // Options
        &wszStringBinding               // Output: binding string
    );

    if (status != RPC_S_OK) {
        return NULL;
    }

    // Convert string binding to binding handle
    status = RpcBindingFromStringBindingW(wszStringBinding, &hBinding);

    // Free the string binding (no longer needed)
    if (wszStringBinding) {
        RpcStringFreeW(&wszStringBinding);
    }

    return (status == RPC_S_OK) ? hBinding : NULL;
}

void STRING_HANDLE_unbind(STRING_HANDLE szString, handle_t hBinding)
{
    (void)szString;
    if (hBinding) {
        RpcBindingFree(&hBinding);
    }
}
