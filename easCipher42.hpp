#ifndef EAS_CIPHER42_H
#define EAS_CIPHER42_H

#include <cstdint>
#include <vector>

constexpr size_t SEED_SIZE = 42;

class easCipher42 {
private:
    bool initialized = false;
    const uint8_t* payload_enc_ciphertext = nullptr;
    size_t payload_enc_ciphertext_len = 0;
    uint8_t seed[SEED_SIZE];
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t salt[16];

public:
    easCipher42() = default;

    bool Init(const uint8_t* payload_enc_data, size_t payload_enc_len);
    bool Decrypt(const uint8_t* ciphertext, size_t len, std::vector<uint8_t>& plaintext);

    const uint8_t* GetSeed() const { return seed; }
    const uint8_t* GetKey() const { return key; }
    const uint8_t* GetIV() const { return iv; }
    const uint8_t* GetSalt() const { return salt; }
    const uint8_t* GetPayloadEncCiphertext() const { return payload_enc_ciphertext; }
    size_t GetPayloadEncCiphertextLen() const { return payload_enc_ciphertext_len; }
};

#endif
