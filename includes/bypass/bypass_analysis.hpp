#ifndef BYPASS_ANALYSIS_H
#define BYPASS_ANALYSIS_H

#include <string>

class easCipher42;

class BypassAnalysis {
private:
    bool verbose = false;
    easCipher42& cipher;

    bool check_virtualization();
    bool check_sleep_timing();

public:
    BypassAnalysis(easCipher42& cipher_ref, bool verbose_mode = false)
        : cipher(cipher_ref), verbose(verbose_mode) {}

    bool run_checks();
};

#endif
