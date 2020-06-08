#include "process_reflection.h"
#include <processsnapshot.h>
#include <iostream>
//#define USE_RTL_PROCESS_REFLECTION

namespace pesieve {
	namespace util {

		typedef struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
		{
			HANDLE ReflectionProcessHandle;
			HANDLE ReflectionThreadHandle;
			DWORD ReflectionClientId;
		} RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, *PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

		// Win >= 7
		NTSTATUS (*NTAPI _RtlCreateProcessReflection)( //from ntdll.dll
			IN HANDLE ProcessHandle,
			IN ULONG Flags,
			IN OPTIONAL PVOID StartRoutine,
			IN OPTIONAL PVOID StartContext,
			IN OPTIONAL HANDLE EventHandle,
			OUT OPTIONAL PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation
			) = NULL;

		// Win >= 8.1
		DWORD (__stdcall *_PssCaptureSnapshot)( //from Kernel32.dll
			HANDLE            ProcessHandle,
			PSS_CAPTURE_FLAGS CaptureFlags,
			DWORD             ThreadContextFlags,
			HPSS              *SnapshotHandle
			) = NULL;

		DWORD (__stdcall *_PssFreeSnapshot)(
			HANDLE ProcessHandle,
			HPSS   SnapshotHandle
			) = NULL;

		DWORD (__stdcall *_PssQuerySnapshot)(
				HPSS SnapshotHandle,
				PSS_QUERY_INFORMATION_CLASS InformationClass,
				void* Buffer,
				DWORD BufferLength
			) = NULL;

		bool load_PssCaptureFreeSnapshot()
		{
			if (_PssCaptureSnapshot == NULL || _PssFreeSnapshot == NULL || _PssQuerySnapshot == NULL) {
				HMODULE lib = LoadLibraryA("kernel32.dll");
				if (!lib) return false;

				FARPROC proc1 = GetProcAddress(lib, "PssCaptureSnapshot");
				if (!proc1) return false;

				FARPROC proc2 = GetProcAddress(lib, "PssFreeSnapshot");
				if (!proc2) return false;

				FARPROC proc3 = GetProcAddress(lib, "PssQuerySnapshot");
				if (!proc3) return false;

				_PssCaptureSnapshot = (DWORD(__stdcall *)(
					HANDLE,
					PSS_CAPTURE_FLAGS,
					DWORD,
					HPSS*
					)) proc1;

				_PssFreeSnapshot = (DWORD(__stdcall *)(
					HANDLE,
					HPSS
					)) proc2;

				_PssQuerySnapshot = (DWORD(__stdcall *)(
					HPSS,
					PSS_QUERY_INFORMATION_CLASS,
					void*,
					DWORD
					)) proc3;
			}
			if (_PssCaptureSnapshot == NULL || _PssFreeSnapshot == NULL || _PssQuerySnapshot == NULL) {
				return false;
			}
			return true;
		}

		bool load_RtlCreateProcessReflection()
		{
			if (_RtlCreateProcessReflection == NULL) {
				HMODULE lib = LoadLibraryA("ntdll.dll");
				if (!lib) return false;

				FARPROC proc = GetProcAddress(lib, "RtlCreateProcessReflection");
				if (!proc) return false;

				_RtlCreateProcessReflection = (NTSTATUS(*NTAPI)(
					IN HANDLE,
					IN ULONG,
					IN OPTIONAL PVOID,
					IN OPTIONAL PVOID,
					IN OPTIONAL HANDLE,
					OUT OPTIONAL PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
					)) proc;
			}
			if (_RtlCreateProcessReflection == NULL) return false;
			return true;
		}

		HANDLE make_process_reflection1(HANDLE orig_hndl)
		{
			if (!load_RtlCreateProcessReflection()) {
				return NULL;
			}
			RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };
			if (_RtlCreateProcessReflection(orig_hndl, 2, 0, 0, 0, &info) == S_OK) {
#ifdef _DEBUG
				std::cout << "Created reflection, PID = " << std::dec << info.ReflectionClientId << "\n";
#endif
				return info.ReflectionProcessHandle;
			}
			return NULL;
		}

		HPSS make_process_snapshot(HANDLE orig_hndl)
		{
			if (!load_PssCaptureFreeSnapshot()) {
				return NULL;
			}
			PSS_CAPTURE_FLAGS capture_flags = (PSS_CAPTURE_FLAGS)PSS_CAPTURE_VA_CLONE
				| PSS_CAPTURE_HANDLES
				| PSS_CAPTURE_HANDLE_NAME_INFORMATION
				| PSS_CAPTURE_HANDLE_BASIC_INFORMATION
				| PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
				| PSS_CAPTURE_HANDLE_TRACE
				| PSS_CAPTURE_THREADS
				| PSS_CAPTURE_THREAD_CONTEXT
				| PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
				| PSS_CAPTURE_VA_SPACE
				| PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION
				| PSS_CREATE_BREAKAWAY
				| PSS_CREATE_BREAKAWAY_OPTIONAL
				| PSS_CREATE_USE_VM_ALLOCATIONS
				| PSS_CREATE_RELEASE_SECTION;

			DWORD thread_ctx_flags = CONTEXT_ALL;
			HPSS snapShot = { 0 };
			DWORD ret = _PssCaptureSnapshot(orig_hndl, capture_flags, 0, &snapShot);
			if (ret != ERROR_SUCCESS) {
#ifdef _DEBUG
				std::cout << "PssCaptureSnapshot failed: " << std::hex << " ret: " << ret << " err: " << GetLastError() << "\n";
#endif
				return NULL;
			}
			return snapShot;
		}

		bool release_process_snapshot(HANDLE procHndl, HANDLE snapshot)
		{
			if (procHndl && snapshot) {
				BOOL is_ok = _PssFreeSnapshot(procHndl, (HPSS)snapshot);
#ifdef _DEBUG
				std::cout << "Released process snapshot\n";
#endif
				return is_ok;
			}
			return false;
		}

		HANDLE make_process_reflection2(HPSS snapshot)
		{
			PSS_VA_CLONE_INFORMATION info = { 0 };
			DWORD ret = _PssQuerySnapshot(snapshot, PSS_QUERY_VA_CLONE_INFORMATION, &info, sizeof(info));
			if (ret != ERROR_SUCCESS) {
				return NULL;
			}
			HANDLE clone = info.VaCloneHandle;
			DWORD clone_pid = GetProcessId(clone);
#ifdef _DEBUG
			std::cout << "Clone PID = " << std::dec << clone_pid << "\n";
#endif
			return info.VaCloneHandle;
		}

	};
};

bool pesieve::util::can_make_process_reflection()
{
#ifdef USE_RTL_PROCESS_REFLECTION
	if (load_RtlCreateProcessReflection()) {
		return true;
	}
#else
	if (load_PssCaptureFreeSnapshot()) {
		return true;
	}
#endif
	return false;
}

HANDLE pesieve::util::make_process_reflection(HANDLE orig_hndl)
{
	HANDLE clone = NULL;
#ifdef USE_RTL_PROCESS_REFLECTION
	clone = make_process_reflection1(orig_hndl);
#else
	HPSS snapshot = make_process_snapshot(orig_hndl);
	clone = make_process_reflection2(snapshot);
	release_process_snapshot(orig_hndl, snapshot);
#endif
	return clone;
}

bool pesieve::util::release_process_reflection(HANDLE* procHndl)
{
	if (procHndl && *procHndl) {
#ifdef _DEBUG
		DWORD clone_pid = GetProcessId(*procHndl);
		std::cout << "Releasing Clone, PID = " << std::dec << clone_pid << "\n";
#endif
		BOOL is_ok = TerminateProcess(*procHndl, 0);
		CloseHandle(*procHndl);
		*procHndl = NULL;
#ifdef _DEBUG
		std::cout << "Released process reflection\n";
#endif
		return is_ok;
	}
	return false;
}
