#ifndef EAS_CIPHER42_H
#define EAS_CIPHER42_H

#include <cstdint>
#include <vector>

class easCipher42 {
private:
    bool initialized = false;
    uint8_t seed[42];
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t salt[16];
    
    // Fodhelper PUR (sans seed)
    const uint8_t* fodhelper_enc = nullptr;
    size_t fodhelper_enc_len = 0;

public:
    easCipher42() = default;
    
    bool Init(const uint8_t* payload_enc_data, size_t payload_enc_len);
    bool Decrypt(const uint8_t* ciphertext, size_t len, std::vector<uint8_t>& plaintext);
    void SetFodhelper(const uint8_t* enc_data, size_t enc_len);
    
    const uint8_t* GetSeed() const { return seed; }
    const uint8_t* GetKey() const { return key; }
    const uint8_t* GetIV() const { return iv; }
    const uint8_t* GetSalt() const { return salt; }
    const uint8_t* GetFodhelperEnc() const { return fodhelper_enc; }
    size_t GetFodhelperEncLen() const { return fodhelper_enc_len; }
};

#endif
