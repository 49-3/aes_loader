#ifndef CRYPTO_FUNCS_H
#define CRYPTO_FUNCS_H

#include <vector>
#include <cstdint>
#include <string>

void sha256(const uint8_t* data, int datalen, uint8_t* out);
void hmac_sha256(const uint8_t* key, int keylen, const uint8_t* data, int datalen, uint8_t* out);
void pbkdf2_sha256(const uint8_t* password, int passwordlen, const uint8_t* salt, int saltlen, 
                   int iterations, int outputlen, uint8_t* output);
void derive_key_iv(const uint8_t* seed, int seedlen, uint8_t* key, uint8_t* iv);
bool AESDecrypt(std::vector<uint8_t>& ciphertext, const uint8_t* key, const uint8_t* iv);  // Reference !

std::string bytes_to_hex(const uint8_t* data, size_t len);

#endif // CRYPTO_FUNCS_H
