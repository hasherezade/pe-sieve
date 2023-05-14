#pragma once

#include <windows.h>

namespace pesieve {
	namespace util {

		BOOL is_process_wow64(IN HANDLE processHandle, OUT BOOL* isProcWow64);
		bool is_process_64bit(IN HANDLE process);

		BOOL wow64_disable_fs_redirection(OUT PVOID* OldValue);
		BOOL wow64_revert_fs_redirection(IN PVOID  OldValue);

		BOOL wow64_get_thread_context(IN HANDLE hThread, IN OUT PWOW64_CONTEXT lpContext);
	};
};
