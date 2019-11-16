#include "process_util.h"
#include <iostream>

HMODULE g_kernel32Hndl = nullptr;

BOOL (WINAPI *g_IsWow64Process)(IN HANDLE, OUT PBOOL) = nullptr;
BOOL (WINAPI *g_Wow64DisableWow64FsRedirection) (OUT PVOID* OldValue) = nullptr;
BOOL (WINAPI *g_Wow64RevertWow64FsRedirection) (IN PVOID OldValue) = nullptr;

HMODULE get_kernel32_hndl()
{
	if (g_kernel32Hndl == nullptr) {
		g_kernel32Hndl = LoadLibraryA("kernel32.dll");
	}
	return g_kernel32Hndl;
}

BOOL is_process_wow64(IN HANDLE processHandle, OUT BOOL* isProcWow64)
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

BOOL wow64_disable_fs_redirection(OUT PVOID* OldValue)
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

BOOL wow64_revert_fs_redirection(IN PVOID OldValue)
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
