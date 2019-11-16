#include "process_util.h"

BOOL is_process_wow64(IN HANDLE processHandle, OUT BOOL* isProcWow64)
{
	if (isProcWow64) {
		(*isProcWow64) = FALSE; //set default output value: FALSE
	}

	HMODULE kernelLib = LoadLibraryA("kernel32.dll");
	if (!kernelLib) return FALSE;

	FARPROC procPtr = GetProcAddress(kernelLib, "IsWow64Process");
	if (!procPtr) return FALSE;

	BOOL (WINAPI *_IsWow64Process)(IN HANDLE, OUT PBOOL) = (BOOL (WINAPI *)(IN HANDLE, OUT PBOOL)) procPtr;
	return _IsWow64Process(processHandle, isProcWow64);
}

BOOL wow64_disable_fs_redirection(OUT PVOID* OldValue)
{
	HMODULE kernelLib = LoadLibraryA("kernel32.dll");
	if (!kernelLib) return FALSE;

	FARPROC procPtr = GetProcAddress(kernelLib, "Wow64DisableWow64FsRedirection");
	if (!procPtr) return FALSE;

	BOOL(WINAPI *_Wow64DisableWow64FsRedirection) (OUT PVOID* OldValue) = (BOOL(WINAPI *) (OUT PVOID* ))procPtr;
	return _Wow64DisableWow64FsRedirection(OldValue);
}

BOOL wow64_revert_fs_redirection(IN PVOID OldValue)
{
	HMODULE kernelLib = LoadLibraryA("kernel32.dll");
	if (!kernelLib) return FALSE;

	FARPROC procPtr = GetProcAddress(kernelLib, "Wow64RevertWow64FsRedirection");
	if (!procPtr) return FALSE;

	BOOL(WINAPI *_Wow64RevertWow64FsRedirection) (IN PVOID OldValue) = (BOOL(WINAPI *) (IN PVOID))procPtr;
	return _Wow64RevertWow64FsRedirection(OldValue);
}
