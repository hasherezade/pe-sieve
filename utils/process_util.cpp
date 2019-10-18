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
