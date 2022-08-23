#include "process_reflection.h"
#include <iostream>

#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
#endif

#ifndef HPSS
#define HPSS HANDLE
#endif

namespace pesieve {
	namespace util {

		typedef struct {
			HANDLE VaCloneHandle;
		} PSS_VA_CLONE_INFORMATION;

		typedef struct  {
			HANDLE UniqueProcess;
			HANDLE UniqueThread;
		} T_CLIENT_ID;

		typedef struct
		{
			HANDLE ReflectionProcessHandle;
			HANDLE ReflectionThreadHandle;
			T_CLIENT_ID ReflectionClientId;
		} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

		// Win >= 7
		NTSTATUS (NTAPI *_RtlCreateProcessReflection) (
			HANDLE ProcessHandle,
			ULONG Flags,
			PVOID StartRoutine,
			PVOID StartContext,
			HANDLE EventHandle,
			T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation
		) = NULL;

		// Win >= 8.1

		typedef enum
		{
			PSS_CAPTURE_NONE = 0x00000000,
			PSS_CAPTURE_VA_CLONE = 0x00000001,
			PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
			PSS_CAPTURE_HANDLES = 0x00000004,
			PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
			PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
			PSS_CAPTURE_THREADS = 0x00000080,
			PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
			PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
			PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
			PSS_CAPTURE_VA_SPACE = 0x00000800,
			PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
			PSS_CAPTURE_IPT_TRACE = 0x00002000,

			PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
			PSS_CREATE_BREAKAWAY = 0x08000000,
			PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
			PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
			PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
			PSS_CREATE_RELEASE_SECTION = 0x80000000
		} PSS_CAPTURE_FLAGS;

		typedef enum
		{
			PSS_QUERY_PROCESS_INFORMATION = 0,
			PSS_QUERY_VA_CLONE_INFORMATION = 1,
			PSS_QUERY_AUXILIARY_PAGES_INFORMATION = 2,
			PSS_QUERY_VA_SPACE_INFORMATION = 3,
			PSS_QUERY_HANDLE_INFORMATION = 4,
			PSS_QUERY_THREAD_INFORMATION = 5,
			PSS_QUERY_HANDLE_TRACE_INFORMATION = 6,
			PSS_QUERY_PERFORMANCE_COUNTERS = 7
		} PSS_QUERY_INFORMATION_CLASS;

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

				_RtlCreateProcessReflection = (NTSTATUS(NTAPI *) (
					HANDLE,
					ULONG,
					PVOID,
					PVOID,
					HANDLE,
					T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION*
				)) proc;

			}
			if (_RtlCreateProcessReflection == NULL) return false;
			return true;
		}

		typedef struct {
			HANDLE orig_hndl;
			HANDLE returned_hndl;
			DWORD returned_pid;
			bool is_ok;
		} t_refl_args;

		DWORD WINAPI refl_creator(LPVOID lpParam)
		{
			t_refl_args *args = static_cast<t_refl_args*>(lpParam);
			if (!args) {
				return !S_OK;
			}
			args->is_ok = false;

			T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };
			NTSTATUS ret = _RtlCreateProcessReflection(args->orig_hndl, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, NULL, NULL, NULL, &info);
			if (ret == S_OK) {
				args->is_ok = true;
				args->returned_hndl = info.ReflectionProcessHandle;
				args->returned_pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(info.ReflectionClientId.UniqueProcess));
			}
			return ret;
		}

		HANDLE make_process_reflection1(HANDLE orig_hndl)
		{
			const DWORD max_wait = 1000;
			if (!load_RtlCreateProcessReflection()) {
				return NULL;
			}

			t_refl_args args = { 0 };
			args.orig_hndl = orig_hndl;

			HANDLE hThead = CreateThread(
				NULL,                   // default security attributes
				0,                      // use default stack size  
				refl_creator,       // thread function name
				&args,          // argument to thread function 
				0,                      // use default creation flags 
				0);   // returns the thread identifier 

			DWORD wait_result = WaitForSingleObject(hThead, max_wait);
			if (wait_result == WAIT_TIMEOUT) {
				std::cerr << "[!] [" << GetProcessId(orig_hndl) << "] Cannot create reflection: timeout passed!\n";
				TerminateThread(hThead, 0);
				CloseHandle(hThead);
				return NULL;
			}
			CloseHandle(hThead);
			if (args.is_ok) {
				if (args.returned_hndl == NULL || args.returned_hndl == INVALID_HANDLE_VALUE) {
					return NULL;
				}
#ifdef _DEBUG
				std::cout << "Created reflection, PID = " << std::dec << args.returned_pid << "\n";
#endif
				return args.returned_hndl;
			}
			return NULL;
		}

		HPSS make_process_snapshot(HANDLE orig_hndl)
		{
			if (!load_PssCaptureFreeSnapshot()) {
				return NULL;
			}
			pesieve::util::PSS_CAPTURE_FLAGS capture_flags = (pesieve::util::PSS_CAPTURE_FLAGS) (PSS_CAPTURE_VA_CLONE
				| PSS_CAPTURE_HANDLES
				| PSS_CAPTURE_HANDLE_NAME_INFORMATION
				| PSS_CAPTURE_HANDLE_BASIC_INFORMATION
				| PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
				//| PSS_CAPTURE_HANDLE_TRACE
				| PSS_CAPTURE_THREADS
				//| PSS_CAPTURE_THREAD_CONTEXT
				//| PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
				| PSS_CAPTURE_VA_SPACE
				| PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION
				| PSS_CREATE_BREAKAWAY
				//| PSS_CREATE_BREAKAWAY_OPTIONAL
				| PSS_CREATE_USE_VM_ALLOCATIONS
				//| PSS_CREATE_RELEASE_SECTION
				);

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

		bool release_process_snapshot(HANDLE procHndl, HPSS snapshot)
		{
			if (procHndl && snapshot) {
				BOOL is_ok = _PssFreeSnapshot(procHndl, snapshot);
#ifdef _DEBUG
				if (is_ok) std::cout << "Released process snapshot\n";
#endif
				return is_ok ? true : false;
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
#ifdef _DEBUG
			DWORD clone_pid = GetProcessId(clone);
			std::cout << "Clone PID = " << std::dec << clone_pid << "\n";
#endif
			return clone;
		}

	};
};

bool pesieve::util::can_make_process_reflection()
{
#ifdef USE_PROCESS_SNAPSHOT
	if (load_PssCaptureFreeSnapshot()) {
		return true;
	}
#endif
#ifdef USE_RTL_PROCESS_REFLECTION
	if (load_RtlCreateProcessReflection()) {
		return true;
	}
#endif
	return false;
}

HANDLE pesieve::util::make_process_reflection(HANDLE orig_hndl)
{
	if (orig_hndl == NULL) {
		return NULL;
	}
	HANDLE clone = NULL;
#ifdef USE_PROCESS_SNAPSHOT
	if (load_PssCaptureFreeSnapshot()) {
		HPSS snapshot = make_process_snapshot(orig_hndl);
		clone = make_process_reflection2(snapshot);
		release_process_snapshot(orig_hndl, snapshot);
		if (clone) {
			return clone;
		}
	}
#endif
#ifdef USE_RTL_PROCESS_REFLECTION
	if (load_RtlCreateProcessReflection()) {
		clone = make_process_reflection1(orig_hndl);
	}
#endif
	return clone;
}

bool pesieve::util::release_process_reflection(HANDLE* procHndl)
{
	if (procHndl == NULL || *procHndl == NULL) {
		return false;
	}
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
	return is_ok ? true : false;
}
