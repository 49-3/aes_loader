#ifndef BYPASS_ANALYSIS_H
#define BYPASS_ANALYSIS_H

#include <string>

class BypassAnalysis {
private:
    bool verbose = false;

    bool check_virtualization();
    bool check_sleep_timing();

public:
    BypassAnalysis(bool verbose_mode = false) : verbose(verbose_mode) {}

    bool run_checks();
};

#endif
