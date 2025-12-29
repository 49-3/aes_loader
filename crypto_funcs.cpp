#include "crypto_funcs.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <sstream>
#include <iomanip>
#include <cstring>

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << int(data[i]);
    }
    return ss.str();
}

void sha256(const uint8_t* data, int datalen, uint8_t* out) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        memset(out, 0, 32);
        return;
    }
    
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        memset(out, 0, 32);
        return;
    }
    
    BCryptHashData(hHash, (PUCHAR)data, datalen, 0);
    BCryptFinishHash(hHash, out, 32, 0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

void hmac_sha256(const uint8_t* key, int keylen, const uint8_t* data, int datalen, uint8_t* out) {
    uint8_t key_padded[64] = {0};
    if (keylen > 64) {
        sha256(key, keylen, key_padded);
        keylen = 32;
    } else {
        memcpy(key_padded, key, keylen);
    }
    
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = key_padded[i] ^ 0x36;
        opad[i] = key_padded[i] ^ 0x5C;
    }
    
    uint8_t inner_data[64 + 320];
    memcpy(inner_data, ipad, 64);
    memcpy(inner_data + 64, data, datalen);
    
    uint8_t inner_hash[32];
    sha256(inner_data, 64 + datalen, inner_hash);
    
    uint8_t outer_data[64 + 32];
    memcpy(outer_data, opad, 64);
    memcpy(outer_data + 64, inner_hash, 32);
    
    sha256(outer_data, 64 + 32, out);
}

void pbkdf2_sha256(const uint8_t* password, int passwordlen, const uint8_t* salt, int saltlen, 
                   int iterations, int outputlen, uint8_t* output) {
    uint8_t u[32], result[32];
    int blocknum = 0;
    int remaining = outputlen;
    uint8_t* outpos = output;
    
    while (remaining > 0) {
        blocknum++;
        int blocksize = remaining > 32 ? 32 : remaining;
        
        uint8_t salt_and_counter[36];
        memcpy(salt_and_counter, salt, saltlen);
        salt_and_counter[saltlen + 0] = (blocknum >> 24) & 0xFF;
        salt_and_counter[saltlen + 1] = (blocknum >> 16) & 0xFF;
        salt_and_counter[saltlen + 2] = (blocknum >>  8) & 0xFF;
        salt_and_counter[saltlen + 3] = (blocknum >>  0) & 0xFF;
        
        hmac_sha256(password, passwordlen, salt_and_counter, saltlen + 4, u);
        memcpy(result, u, 32);
        
        for (int i = 1; i < iterations; i++) {
            uint8_t u_prev[32];
            memcpy(u_prev, u, 32);
            hmac_sha256(password, passwordlen, u_prev, 32, u);
            for (int j = 0; j < 32; j++) {
                result[j] ^= u[j];
            }
        }
        
        memcpy(outpos, result, blocksize);
        outpos += blocksize;
        remaining -= blocksize;
    }
}

void derive_key_iv(const uint8_t* seed, int seedlen, uint8_t* key, uint8_t* iv) {
    uint8_t sha256_out[32];
    sha256(seed, 16, sha256_out);
    
    // SALT = SHA256(seed[:16])
    uint8_t salt[16];
    memcpy(salt, sha256_out, 16);
    
    uint8_t key_iv[48] = {0};
    pbkdf2_sha256(seed, seedlen, salt, 16, 100000, 48, key_iv);
    
    memcpy(key, key_iv, 32);
    memcpy(iv, key_iv + 32, 16);
}

bool AESDecrypt(std::vector<uint8_t>& ciphertext, const uint8_t* key, const uint8_t* iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;
    
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, 
                              (PUCHAR)BCRYPT_CHAIN_MODE_CBC, 
                              sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    DWORD cbKeyObject = 0;
    DWORD cbData = 0;
    status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, 
                              (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    std::vector<BYTE> keyObject(cbKeyObject);
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), cbKeyObject, 
                                       (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    DWORD cbDecrypted = 0;
    std::vector<uint8_t> decrypted(ciphertext.size() + 16);
    
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(), 
                          NULL, (PUCHAR)iv, 16, decrypted.data(), (ULONG)decrypted.size(), 
                          &cbDecrypted, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    // **PKCS7 UNPADDING CORRECT**
    if (cbDecrypted == 0 || cbDecrypted > decrypted.size()) {
        return false;
    }
    
    uint8_t pad_len = decrypted[cbDecrypted - 1];
    if (pad_len == 0 || pad_len > 16) {
        return false;
    }
    
    // Vérifier padding valide
    for (uint8_t i = 1; i <= pad_len; i++) {
        if (decrypted[cbDecrypted - i] != pad_len) {
            return false;
        }
    }
    
    // Copier données sans padding
    ciphertext.clear();
    ciphertext.resize(cbDecrypted - pad_len);
    std::memcpy(ciphertext.data(), decrypted.data(), cbDecrypted - pad_len);
    
    return true;
}
