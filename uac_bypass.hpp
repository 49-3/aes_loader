#ifndef UAC_BYPASS_H
#define UAC_BYPASS_H

#include <string>
#include <vector>

class UACBypass {
private:
    bool verbose = false;
    std::string loader_path;
    std::string args;

public:
    UACBypass(const std::string& path, const std::string& cmdline_args, bool verbose_mode = false)
        : loader_path(path), args(cmdline_args), verbose(verbose_mode) {}

    bool execute_fodhelper();
};

#endif
