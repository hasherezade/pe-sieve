#include "process_minidump.h"
#include "process_privilege.h"
#include <dbghelp.h>

namespace pesieve {
	namespace util {

		BOOL(CALLBACK *_MiniDumpWriteDump)(
			HANDLE                            hProcess,
			DWORD                             ProcessId,
			HANDLE                            hFile,
			MINIDUMP_TYPE                     DumpType,
			PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
			PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
			PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
			) = NULL;

		bool load_MiniDumpWriteDump()
		{
			if (_MiniDumpWriteDump != NULL) {
				return true; // already loaded
			}
			HMODULE lib = LoadLibraryA("dbghelp.dll");
			if (!lib) return false;

			FARPROC proc = GetProcAddress(lib, "MiniDumpWriteDump");
			if (!proc) {
				FreeLibrary(lib);
				return false;
			}
			_MiniDumpWriteDump = (BOOL(CALLBACK *)(
				HANDLE,
				DWORD,
				HANDLE,
				MINIDUMP_TYPE,
				PMINIDUMP_EXCEPTION_INFORMATION,
				PMINIDUMP_USER_STREAM_INFORMATION,
				PMINIDUMP_CALLBACK_INFORMATION
				)) proc;

			if (_MiniDumpWriteDump != NULL) {
				return true; // loaded
			}
			return false;
		}

	};
};


bool pesieve::util::make_minidump(DWORD pid, const std::string &out_file)
{
	if (!load_MiniDumpWriteDump()) return false;

	HANDLE procHndl  = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (procHndl == NULL) {
		DWORD last_err = GetLastError();
		if (last_err == ERROR_ACCESS_DENIED) {
			if (set_debug_privilege()) {
				procHndl = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
			}
		}
	}
	if (procHndl == NULL) {
		return false;
	}
	HANDLE outFile = CreateFileA(out_file.c_str(), GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (outFile == INVALID_HANDLE_VALUE) {
		CloseHandle(procHndl);
		return false;
	}

	BOOL isDumped = _MiniDumpWriteDump(procHndl, pid, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	CloseHandle(outFile);
	CloseHandle(procHndl);
	return (isDumped) ? true : false;
}
