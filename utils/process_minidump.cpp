#include "process_minidump.h"

#include <dbghelp.h>

BOOL (*_MiniDumpWriteDump)(
	HANDLE                            hProcess,
	DWORD                             ProcessId,
	HANDLE                            hFile,
	MINIDUMP_TYPE                     DumpType,
	PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
	PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
	) = NULL;


bool load_minidump_func()
{
	if (_MiniDumpWriteDump != NULL) {
		return true; // already loaded
	}
	HMODULE lib = LoadLibraryA("dbghelp.dll");
	if (!lib) return false;

	FARPROC proc = GetProcAddress(lib, "MiniDumpWriteDump");
	if (!proc) return false;

	_MiniDumpWriteDump = (BOOL(*)(
		HANDLE,
		DWORD,
		HANDLE,
		MINIDUMP_TYPE,
		PMINIDUMP_EXCEPTION_INFORMATION,
		PMINIDUMP_USER_STREAM_INFORMATION,
		PMINIDUMP_CALLBACK_INFORMATION
	)) proc;
	return true;
}

bool make_minidump(DWORD pid, std::string out_file)
{
	if (!load_minidump_func()) return false;

	HANDLE procHndl  = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (procHndl == INVALID_HANDLE_VALUE) return false;

	HANDLE outFile = CreateFileA(out_file.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (outFile == INVALID_HANDLE_VALUE) {
		CloseHandle(procHndl);
		return false;
	}
	BOOL isDumped = _MiniDumpWriteDump(procHndl, pid, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	CloseHandle(outFile);
	CloseHandle(procHndl);
	return isDumped;
}
