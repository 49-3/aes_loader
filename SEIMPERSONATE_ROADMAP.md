# SeImpersonate Integration Roadmap

## 📚 Context Analysis

### OSEP Course Understanding (16.2.2)
Your OSEP material explains the **Print Spooler Bug** attack chain:

1. **Trigger**: Abuse RPC calls (`RpcOpenPrinter` + `RpcRemoteFindFirstPrinterChangeNotificationEx`)
2. **Pipe Trick**: Use path normalization with forward slash (`\\host/pipe/name`) to bypass validation
3. **Result**: Force SYSTEM service to connect to attacker's named pipe
4. **Impersonation**: Call `ImpersonateNamedPipeClient()` to steal SYSTEM token
5. **Execution**: Use `DuplicateTokenEx()` + `CreateProcessAsUser()` to spawn payload as SYSTEM

### Current Loader Capabilities
Your **AES Loader** has:
- ✅ 4 injection modes (DEFAULT, HOLLOW, APC, UAC)
- ✅ PPID spoofing
- ✅ Anti-analysis checks
- ✅ AES-CBC encryption (seed-based)
- ✅ Smart PE vs shellcode detection
- ⏳ **MISSING**: SeImpersonate privilege escalation

### PrintSpoofer C++ Implementation
The repo contains a complete, production-ready implementation:
- `PrintSpoofer.cpp`: Main logic (599 lines)
- RPC stubs generated from `ms-rprn.idl`
- Handles Visual Studio compilation
- **Issue**: RPC stubs compiled with MIDL, not compatible with MinGW

---

## 🎯 Approach Analysis & Feasibility

### Option A: Call External SpoolSample Tool ⭐ (Phase 1)
**Concept**: Loader waits for external `SpoolSample.exe` connection

**Pros**:
- ✅ No compilation issues (spoolsample already exists)
- ✅ Modular separation (OSINT-safe)
- ✅ Tests impersonation mechanics without RPC stubs
- ✅ Can validate token stealing works with your payload injection

**Cons**:
- ❌ Requires 2 separate executables
- ❌ Attacker must run SpoolSample externally
- ❌ Not autonomous

**Feasibility**: **VERY HIGH** - Ready to test immediately

---

### Option B: Embed DLL with RPC Stubs (Phase 2) ⭐⭐ (PLANNED)
**Concept**: Compile PrintSpoofer code as DLL in Visual Studio, embed in loader, trigger internally

**Key Challenge**: RPC stub compilation
- `ms-rprn.idl` → MIDL compiler → `ms-rprn_h.h`, `ms-rprn_c.c`
- MinGW **cannot** compile MIDL-generated stubs
- **Solution**: Compile DLL on Windows with Visual Studio, then embed

**Pros**:
- ✅ Fully autonomous (single executable)
- ✅ Production-ready (PrintSpoofer is battle-tested)
- ✅ OPSEC: No external tools needed
- ✅ Scalable for Red Team ops

**Cons**:
- ⚠️ Requires Windows + Visual Studio (one-time build)
- ⚠️ Slightly larger binary (embedded DLL)
- ⚠️ Need to port PrintSpoofer logic to DLL interface

**Feasibility**: **HIGH** - PrintSpoofer code exists, just needs adaptation

---

## 🛣️ Detailed Roadmap

### Phase 1: Validation (Current - Days 1-2)
**Goal**: Prove SeImpersonate + payload injection chain works

#### 1.1 Extend Loader with `-i` Flag
```
loader.exe -i [OTHER_OPTIONS]
```
- Add `-i` flag to `Config` struct in `loader.cpp`
- When `-i` set, spawn named pipe server instead of direct injection
- Listen for SYSTEM connection from external SpoolSample

#### 1.2 Named Pipe Server Implementation (C++)
Create new file: `seimpersonate.cpp` / `seimpersonate.hpp`

Key functions:
```cpp
class SeImpersonateHandler {
    HANDLE hNamedPipe;
    std::vector<uint8_t> payload;
    bool verbose;

public:
    bool CreatePipeServer(const std::string& pipeName);
    bool WaitForConnection(DWORD timeoutMs = 5000);
    bool ImpersonateAndInject();
};
```

Logic flow:
1. Generate random UUID for pipe name
2. Create named pipe: `\\.\pipe\[RANDOM]\pipe\spoolss`
3. Wait for connection from spoolsv.exe (triggered externally)
4. `ImpersonateNamedPipeClient()` when connected
5. `OpenThreadToken()` + `DuplicateTokenEx()` to get primary SYSTEM token
6. Inject payload using existing `ProcessInjection` class into new process

#### 1.3 SpoolSample Integration
On attacker machine:
```bash
# Terminal 1: Start your loader
loader.exe -i -m apc

# Terminal 2: Trigger spooler coercion
SpoolSample.exe [TARGET_IP] [TARGET_IP]/pipe/[RANDOM_NAME]
```

#### 1.4 Testing & Validation
- [ ] Pipe created successfully
- [ ] SpoolSample connects (verify via netstat/procmon)
- [ ] SYSTEM token impersonated (check SID S-1-5-18)
- [ ] Payload executes as SYSTEM
- [ ] Log output shows success

**Deliverable**: Loader runs SYSTEM payload with external coercion tool

---

### Phase 2: Autonomous DLL Integration (Days 3-5)
**Goal**: Remove dependency on external SpoolSample

#### 2.1 Compile PrintSpoofer as DLL (Windows VM)
On Windows with Visual Studio:
```bash
# Modify PrintSpoofer.cpp
# 1. Extract core RPC logic into functions
# 2. Create DLL export interface:
typedef BOOL (*PFN_RPC_TRIGGER)(const wchar_t* pipeName);
extern "C" __declspec(dllexport) BOOL TriggerPrinterBug(const wchar_t* pipeName);
```

Steps:
- [ ] Open `PrintSpoofer.sln` in Visual Studio
- [ ] Add DLL project (copy PrintSpoofer sources)
- [ ] Keep MIDL-generated stubs (Visual Studio handles this)
- [ ] Export `TriggerPrinterBug()` function
- [ ] Compile to `printspoofer.dll`
- [ ] Copy DLL binary

#### 2.2 Embed DLL in Loader Binary
Create: `dllloader.cpp` / `dllloader.hpp`

```cpp
class EmbeddedPrinterBugDLL {
    const uint8_t* dllData;
    size_t dllSize;
    HMODULE hModule;

public:
    bool LoadFromMemory(const uint8_t* data, size_t size);
    bool TriggerSpoolerCoercion(const std::string& pipeName);
};
```

Process:
1. Base64 encode compiled `printspoofer.dll`
2. Embed encoded data as static array in C++
3. At runtime: Decode → Write to temp location → LoadLibraryW()
4. Call `TriggerPrinterBug()` exported function

#### 2.3 Update Loader Main Logic
```cpp
if (cfg.mode == InjectionMode::IMPERSONATE) {
    std::cout << "[*] SeImpersonate mode...\n";

    SeImpersonateHandler impersonator(cfg.verbose);
    std::string pipeName = generate_uuid();

    // 1. Create named pipe server
    if (!impersonator.CreatePipeServer(pipeName)) {
        std::cout << "[-] Pipe creation failed\n";
        return -1;
    }

    // 2. Trigger printer bug with embedded DLL
    EmbeddedPrinterBugDLL bugDLL;
    if (!bugDLL.LoadFromMemory(EMBEDDED_DLL_DATA, EMBEDDED_DLL_SIZE)) {
        std::cout << "[-] DLL load failed\n";
        return -1;
    }

    // 3. Wait for connection & inject
    if (impersonator.WaitForConnection(5000) &&
        impersonator.ImpersonateAndInject(payload)) {
        std::cout << "[+] SUCCESS\n";
        return 0;
    }
    return -1;
}
```

#### 2.4 Full Autonomous Testing
```bash
loader.exe -i -m impersonate
# [+] Named pipe listening...
# [+] Printer bug triggered internally...
# [+] SYSTEM token impersonated...
# [+] Payload injected as SYSTEM
```

**Deliverable**: Single `loader.exe` achieves SeImpersonate escalation autonomously

---

## 📋 Implementation Checklist

### Phase 1 Tasks
- [ ] Read/analyze PrintSpoofer.cpp source (DONE ✓)
- [ ] Create `seimpersonate.hpp` header file
- [ ] Create `seimpersonate.cpp` implementation
  - [ ] Named pipe creation (`CreateSpoolNamedPipe()`)
  - [ ] Connection handling (`ImpersonateNamedPipeClient()`)
  - [ ] Token duplication logic
  - [ ] Process creation with stolen token
- [ ] Add `-i` flag to loader argument parser
- [ ] Add new injection mode conditional
- [ ] Test with external SpoolSample (manual trigger)
- [ ] Validate SYSTEM execution
- [ ] Document usage in USAGE.md

### Phase 2 Tasks (Future)
- [ ] Setup Windows VM with Visual Studio
- [ ] Clone PrintSpoofer repo in Visual Studio
- [ ] Adapt to DLL format (extract exports)
- [ ] Compile printspoofer.dll
- [ ] Create DLL embedding utility
- [ ] Integrate into loader
- [ ] Test autonomous operation
- [ ] Code obfuscation/AES encryption of embedded DLL
- [ ] Final integration tests

---

## 🔒 OPSEC Considerations

### Phase 1 (External SpoolSample)
- **Risk**: Two executables on target = higher detection
- **Mitigation**:
  - Obfuscate both binaries
  - Use temporary locations
  - Clean up artifacts
  - Monitor for EDR hooks on pipe operations

### Phase 2 (Autonomous DLL)
- **Risk**: Embedded DLL is recognizable signature
- **Mitigation**:
  - Encrypt DLL payload with AES (like main payload)
  - Decode in memory only
  - Use legitimate process isolation
  - Spoof parent process (PPID) before escalation

### General Mitigations
- SeImpersonate abuse is well-known, expect detection
- Modern Windows has improved print spooler validation
- Test on Windows 10 21H2+, Windows 11, Server 2022 for compatibility
- Consider alternative: Fax Machine bug (similar, less detected)

---

## 🎓 Technical Deep-Dive

### Print Spooler Bug Chain

```
┌─────────────────────────────────────┐
│ 1. Create Named Pipe                │
│    \\.\pipe\RANDOM\pipe\spoolss      │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│ 2. RPC Call: RpcOpenPrinter()       │
│    (Get printer server handle)       │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│ 3. RPC Call: RpcRemoteFindFirst...  │
│    (Register change notifications)  │
│    Target: \\host/pipe/RANDOM       │
│    (Forward slash forces            │
│     path normalization bypass)      │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│ 4. spoolsv.exe (SYSTEM) connects to │
│    our named pipe                   │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│ 5. ImpersonateNamedPipeClient()     │
│    Current thread now has SYSTEM    │
│    token (impersonation level)      │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│ 6. DuplicateTokenEx()               │
│    Convert impersonation → primary  │
│    token for process creation       │
└─────────────────────────────────────┘
                 ↓
┌─────────────────────────────────────┐
│ 7. CreateProcessAsUser()            │
│    Spawn process as SYSTEM          │
│    (or CreateProcessWithTokenW)     │
└─────────────────────────────────────┘
```

### Key APIs Used
| API | Purpose | Phase |
|-----|---------|-------|
| `CreateNamedPipe()` | Create server pipe | 1 |
| `ConnectNamedPipe()` | Wait for connection | 1 |
| `RpcOpenPrinter()` | Get printer handle | 1.3 |
| `RpcRemoteFindFirstPrinterChangeNotificationEx()` | Trigger coercion | 1.3 |
| `ImpersonateNamedPipeClient()` | Steal token | 1 |
| `OpenThreadToken()` | Get impersonated token handle | 1 |
| `DuplicateTokenEx()` | Convert to primary token | 1 |
| `CreateProcessAsUser()` | Execute as SYSTEM | 1 |
| `CreateProcessWithTokenW()` | Fallback execution | 1 |

---

## ⚠️ Known Issues & Mitigation

| Issue | Root Cause | Solution |
|-------|-----------|----------|
| MinGW can't compile RPC stubs | MIDL output ↔ Visual Studio only | Use pre-compiled DLL from Windows |
| Path validation in spooler | Windows checks pipe name | Use forward slash bypass (already in code) |
| Timeout on older Windows | RPC timing issues | Increase wait timeout, add retries |
| SeImpersonate might be removed | Modern hardening | Detect & fallback to other privesc |
| Named pipe detection | EDR monitors named pipes | Randomize names, use legitimate patterns |

---

## 📊 Success Metrics

### Phase 1
- ✅ Loader accepts `-i` flag without errors
- ✅ Named pipe created and listening
- ✅ External SpoolSample triggers connection
- ✅ Payload executes as SYSTEM user (verify via whoami)
- ✅ No crashes or exceptions

### Phase 2
- ✅ Single loader.exe works standalone
- ✅ Embedded DLL loads without crashes
- ✅ RPC calls succeed (no timeout)
- ✅ Full SYSTEM escalation in < 5 seconds
- ✅ Binary size reasonable (< 5MB uncompressed)

---

## 📝 References

- **OSEP 16.2.2**: Elevation with Impersonation (in context)
- **PrintSpoofer**: https://github.com/itm4n/PrintSpoofer
- **SpoolSample**: https://github.com/leechristensen/SpoolSample
- **Blog**: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
- **MS-RPRN Protocol**: Print System Remote Protocol documentation

---

## 🚀 Next Steps

1. **START HERE**: Read this document carefully
2. **Phase 1 Prep**: Review `seimpersonate.hpp` design below
3. **Phase 1 Build**: Implement C++ named pipe logic
4. **Phase 1 Test**: Run with external SpoolSample
5. **Phase 2 Plan**: Setup Windows compilation environment
6. **Phase 2 Build**: Compile PrintSpoofer as DLL
7. **Phase 2 Integrate**: Embed DLL into loader
8. **Final Test**: Autonomous SYSTEM execution

---

## 🏗️ Proposed seimpersonate.hpp

```cpp
#ifndef SEIMPERSONATE_H
#define SEIMPERSONATE_H

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

class SeImpersonateHandler {
private:
    HANDLE hNamedPipe = INVALID_HANDLE_VALUE;
    HANDLE hPipeEvent = INVALID_HANDLE_VALUE;
    HANDLE hTriggerThread = INVALID_HANDLE_VALUE;

    std::string pipeName;
    std::vector<uint8_t> payload;
    bool verbose = false;

    // Helper methods
    bool GenerateRandomPipeName(std::string& outName);
    bool CreatePipeServer(const std::string& name);
    bool TriggerPrinterBug(const std::string& name);

public:
    SeImpersonateHandler(bool verboseMode = false) : verbose(verboseMode) {}
    ~SeImpersonateHandler();

    // Main interface
    bool Execute(const std::vector<uint8_t>& payloadData);

    // Getters
    const std::string& GetPipeName() const { return pipeName; }
};

#endif // SEIMPERSONATE_H
```

---

**Status**: ✏️ Ready for Phase 1 implementation
**Estimated Time**:
- Phase 1: 4-6 hours (validation)
- Phase 2: 8-12 hours (full autonomy)
