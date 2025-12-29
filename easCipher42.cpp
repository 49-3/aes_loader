#include "easCipher42.hpp"
#include "crypto_funcs.hpp"
#include <cstring>

bool easCipher42::Init(const uint8_t* payload_enc_data, size_t payload_enc_len) {
    if (payload_enc_len < 42) return false;
    
    // EXTRAIRE seed de payload_enc[0:42]
    memcpy(seed, payload_enc_data, 42);
    
    // Salt = SHA256(seed[0:16])
    uint8_t seed_prefix[16];
    memcpy(seed_prefix, seed, 16);
    sha256(seed_prefix, 16, salt);
    
    derive_key_iv(seed, 42, key, iv);
    initialized = true;
    return true;
}

void easCipher42::SetFodhelper(const uint8_t* enc_data, size_t enc_len) {
    fodhelper_enc = enc_data;
    fodhelper_enc_len = enc_len;
}

bool easCipher42::Decrypt(const uint8_t* ciphertext, size_t len, std::vector<uint8_t>& plaintext) {
    if (!initialized) return false;
    
    std::vector<uint8_t> encrypteddata(ciphertext, ciphertext + len);
    bool result = AESDecrypt(encrypteddata, key, iv);
    if (result) {
        plaintext = std::move(encrypteddata);
    }
    return result;
}
