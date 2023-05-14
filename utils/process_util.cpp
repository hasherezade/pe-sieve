#include "process_util.h"
#include <iostream>

namespace pesieve {
	namespace util {
		HMODULE g_kernel32Hndl = nullptr;

		BOOL(WINAPI *g_IsWow64Process)(IN HANDLE, OUT PBOOL) = nullptr;
		BOOL(WINAPI *g_Wow64DisableWow64FsRedirection) (OUT PVOID* OldValue) = nullptr;
		BOOL(WINAPI *g_Wow64RevertWow64FsRedirection) (IN PVOID OldValue) = nullptr;
		BOOL(WINAPI *g_Wow64GetThreadContext)(IN HANDLE hThread, IN OUT PWOW64_CONTEXT lpContext) = nullptr;

		HMODULE get_kernel32_hndl()
		{
			const char kernel32_dll[] = "kernel32.dll";
			if (!g_kernel32Hndl) {
				g_kernel32Hndl = GetModuleHandleA(kernel32_dll);
			}
			if (!g_kernel32Hndl) {
				g_kernel32Hndl = LoadLibraryA(kernel32_dll);
			}
			return g_kernel32Hndl;
		}
	};
};

BOOL pesieve::util::is_process_wow64(IN HANDLE processHandle, OUT BOOL* isProcWow64)
{
	if (isProcWow64) {
		(*isProcWow64) = FALSE; //set default output value: FALSE
	}
	if (!g_IsWow64Process) {
		HMODULE kernelLib = get_kernel32_hndl();
		if (!kernelLib) return FALSE;

		FARPROC procPtr = GetProcAddress(kernelLib, "IsWow64Process");
		if (!procPtr) return FALSE;

		g_IsWow64Process = (BOOL(WINAPI *)(IN HANDLE, OUT PBOOL))procPtr;
	}
	if (!g_IsWow64Process) {
		return FALSE;
	}
	return g_IsWow64Process(processHandle, isProcWow64);
}

bool pesieve::util::is_process_64bit(IN HANDLE process)
{
	BOOL isScanner32bit = TRUE;
#ifdef _WIN64 //is the scanner 64 bit?
	isScanner32bit = FALSE;
#endif
	BOOL isScannerWow64 = FALSE;
	pesieve::util::is_process_wow64(GetCurrentProcess(), &isScannerWow64);

	const BOOL isSystem64bit = !isScanner32bit || isScannerWow64;
	if (!isSystem64bit) {
		//the system is not 64 bit, so for sure the app is 32 bit
		return false; 
	}

	BOOL isProcessWow = FALSE;
	pesieve::util::is_process_wow64(process, &isProcessWow);

	if (isProcessWow) {
		// the system is 64 bit, and the process runs as Wow64, so it is 32 bit
		return false;
	}
	// the system is 64 bit, and the process runs NOT as Wow64, so it is 64 bit
	return true;
}

BOOL pesieve::util::wow64_get_thread_context(IN HANDLE hThread, IN OUT PWOW64_CONTEXT lpContext)
{
#ifdef _WIN64
	if (!g_Wow64GetThreadContext) {
		HMODULE kernelLib = get_kernel32_hndl();
		if (!kernelLib) return FALSE;

		FARPROC procPtr = GetProcAddress(get_kernel32_hndl(), "Wow64GetThreadContext");
		if (!procPtr) return FALSE;

		g_Wow64GetThreadContext = (BOOL(WINAPI*)(IN HANDLE, IN OUT PWOW64_CONTEXT))procPtr;
	}
	return g_Wow64GetThreadContext(hThread, lpContext);
#else
	return FALSE;
#endif
}

BOOL pesieve::util::wow64_disable_fs_redirection(OUT PVOID* OldValue)
{
	if (!g_Wow64DisableWow64FsRedirection) {
		HMODULE kernelLib = get_kernel32_hndl();
		if (!kernelLib) return FALSE;

		FARPROC procPtr = GetProcAddress(kernelLib, "Wow64DisableWow64FsRedirection");
		if (!procPtr) return FALSE;

		g_Wow64DisableWow64FsRedirection = (BOOL(WINAPI *) (OUT PVOID*))procPtr;
	}
	if (!g_Wow64DisableWow64FsRedirection) {
		return FALSE;
	}
	return g_Wow64DisableWow64FsRedirection(OldValue);
}

BOOL pesieve::util::wow64_revert_fs_redirection(IN PVOID OldValue)
{
	if (!g_Wow64RevertWow64FsRedirection) {
		HMODULE kernelLib = get_kernel32_hndl();
		if (!kernelLib) return FALSE;

		FARPROC procPtr = GetProcAddress(kernelLib, "Wow64RevertWow64FsRedirection");
		if (!procPtr) return FALSE;

		g_Wow64RevertWow64FsRedirection = (BOOL(WINAPI *) (IN PVOID))procPtr;
	}
	if (!g_Wow64RevertWow64FsRedirection) {
		return FALSE;
	}
	return g_Wow64RevertWow64FsRedirection(OldValue);
}
