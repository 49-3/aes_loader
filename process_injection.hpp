#ifndef PROCESS_INJECTION_H
#define PROCESS_INJECTION_H

#include <windows.h>
#include <cstdint>
#include <vector>

class ProcessInjection {
private:
    HANDLE hProcess = nullptr;
    HANDLE hThread = nullptr;
    DWORD processId = 0;
    bool verbose = false;

public:
    ProcessInjection(bool verbose_mode = false) : verbose(verbose_mode) {}
    ~ProcessInjection();

    // APC injection into existing process
    bool InjectViaAPC(DWORD target_pid, const std::vector<uint8_t>& payload);

    bool IsValid() const { return hProcess && hProcess != INVALID_HANDLE_VALUE; }
};

#endif
