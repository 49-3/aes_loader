#include "easCipher42.hpp"
#include "crypto_funcs.hpp"
#include <cstring>
#include <iostream>

bool easCipher42::Init(const uint8_t* payload_enc_data, size_t payload_enc_len) {
    if (payload_enc_len < SEED_SIZE) return false;

    try {
        // EXTRAIRE seed de payload_enc[0:SEED_SIZE]
        memcpy(seed, payload_enc_data, SEED_SIZE);

        // STOCKER le pointeur et la taille du ciphertext SANS seed
        payload_enc_ciphertext = payload_enc_data + SEED_SIZE;
        payload_enc_ciphertext_len = payload_enc_len - SEED_SIZE;

        // Salt = SHA256(seed[0:16])
        uint8_t seed_prefix[16];
        memcpy(seed_prefix, seed, 16);
        sha256(seed_prefix, 16, salt);

        derive_key_iv(seed, SEED_SIZE, key, iv);
        initialized = true;
        return true;
    } catch (const std::bad_alloc& e) {
        std::cerr << "[-] Init bad_alloc: " << e.what() << "\n";
        return false;
    }
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
