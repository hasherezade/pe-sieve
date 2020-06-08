#pragma once

#include <Windows.h>

namespace pesieve {
	namespace util {

#ifdef USE_RTL_PROCESS_REFLECTION
		const DWORD reflection_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE;
#else
		const DWORD reflection_access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS;
#endif

		bool can_make_process_reflection();
		HANDLE make_process_reflection(HANDLE orig_hndl);
		bool release_process_reflection(HANDLE* reflection_hndl);

	};
};
