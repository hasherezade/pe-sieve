#include "threads_util.h"

#include <peconv.h>
#include <tlhelp32.h>
#include "../utils/ntddk.h"
#include "custom_buffer.h"

#ifdef _DEBUG
#include <iostream>
#endif


namespace pesieve {
	namespace util {

		// Thread info structures:
		typedef struct _THREAD_LAST_SYSCALL_INFORMATION
		{
			PVOID FirstArgument;
			USHORT SystemCallNumber;
		} THREAD_LAST_SYSCALL_INFORMATION, * PTHREAD_LAST_SYSCALL_INFORMATION;


		bool query_thread_details(IN DWORD tid, OUT pesieve::util::thread_info& info)
		{
			static auto mod = GetModuleHandleA("ntdll.dll");
			if (!mod) return false;

			static auto pNtQueryInformationThread = reinterpret_cast<decltype(&NtQueryInformationThread)>(GetProcAddress(mod, "NtQueryInformationThread"));
			if (!pNtQueryInformationThread)  return false;

			const DWORD thAccess = THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT;
			HANDLE hThread = OpenThread(thAccess, 0, tid);
			if (!hThread) {
				hThread = OpenThread(THREAD_QUERY_INFORMATION, 0, tid);
				if (!hThread) return false;
			}
			bool isOk = false;
			ULONG returnedLen = 0;
			LPVOID startAddr = 0;
			NTSTATUS status = 0;
			status = pNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddr, sizeof(LPVOID), &returnedLen);
			if (status == 0 && returnedLen == sizeof(startAddr)) {
				info.start_addr = (ULONGLONG)startAddr;
				isOk = true;
			}
			returnedLen = 0;
			THREAD_LAST_SYSCALL_INFORMATION syscallInfo = { 0 };
			status = pNtQueryInformationThread(hThread, ThreadLastSystemCall, &syscallInfo, sizeof(syscallInfo), &returnedLen);
			if (status == 0 && returnedLen == sizeof(syscallInfo)) {
				info.last_syscall = syscallInfo.SystemCallNumber;
				isOk = true;
			}
			CloseHandle(hThread);
			return isOk;
		}

	}; // namespace util
}; // namespace pesieve


bool pesieve::util::query_threads_details(IN OUT std::map<DWORD, pesieve::util::thread_info>& threads_info)
{
	for (auto itr = threads_info.begin(); itr != threads_info.end(); ++itr) {
		pesieve::util::thread_info& info = itr->second;
		if (!query_thread_details(info.tid, info)) return false;
	}
	return true;
}

bool pesieve::util::fetch_threads_info(IN DWORD pid, OUT std::map<DWORD, thread_info>& threads_info)
{
	AutoBuffer bBuf;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	while (status != STATUS_SUCCESS) {
		ULONG ret_len = 0;
		status = NtQuerySystemInformation(SystemProcessInformation, bBuf.buf, bBuf.buf_size, &ret_len);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			if (!bBuf.alloc(ret_len)) {
				return false;
			}
			continue; // try again
		}
		break; //other error, or success
	};

	if (status != STATUS_SUCCESS) {
		return false;
	}

	bool found = false;
	SYSTEM_PROCESS_INFORMATION* info = (SYSTEM_PROCESS_INFORMATION*)bBuf.buf;
	while (info) {
		if (info->UniqueProcessId == pid) {
			found = true;
			break;
		}
		if (!info->NextEntryOffset) {
			break;
		}
		size_t record_size = info->NextEntryOffset;
		if (record_size < sizeof(SYSTEM_PROCESS_INFORMATION)) {
			// Record size smaller than expected, probably it is an old system that doesn not support the new version of this API
#ifdef _DEBUG
			std::cout << "The new version of SYSTEM_PROCESS_INFORMATION is not supported!\n";
#endif
			break;
		}
		info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)info + info->NextEntryOffset);
		if (!peconv::validate_ptr(bBuf.buf, bBuf.buf_size, info, sizeof(SYSTEM_PROCESS_INFORMATION))) {
			break;
		}
	}

	if (!found) {
		return false;
	}

	const size_t thread_count = info->NumberOfThreads;
	for (size_t i = 0; i < thread_count; i++) {
		
		const DWORD tid = MASK_TO_DWORD((ULONGLONG)info->Threads[i].ClientId.UniqueThread);
		auto itr = threads_info.find(tid);
		if (itr == threads_info.end()) {
			threads_info[tid] = thread_info(tid);
		}
		thread_info &threadi = threads_info[tid];
		threadi.is_extended = true;
		threadi.ext.sys_start_addr = (ULONG_PTR)info->Threads[i].StartAddress;
		threadi.ext.state = info->Threads[i].ThreadState;
		threadi.ext.wait_reason = info->Threads[i].WaitReason;
		threadi.ext.wait_time  = info->Threads[i].WaitTime;
	}
	return true;
}

bool pesieve::util::fetch_threads_by_snapshot(IN DWORD pid, OUT std::map<DWORD, thread_info>& threads_info)
{
	HANDLE hThreadSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnapShot == INVALID_HANDLE_VALUE) {
		const DWORD err = GetLastError();
#ifdef _DEBUG
		std::cerr << "[-] Could not create threads snapshot. Error: " << std::dec << err << std::endl;
#endif
		return false;
	}
	THREADENTRY32 th32 = { 0 };
	th32.dwSize = sizeof(THREADENTRY32);

	//check all threads in the process:
	if (!Thread32First(hThreadSnapShot, &th32)) {
		CloseHandle(hThreadSnapShot);
#ifdef _DEBUG
		std::cerr << "[-] Could not enumerate thread. Error: " << GetLastError() << std::endl;
#endif
		return false;
	}
	do {
		if (th32.th32OwnerProcessID != pid) {
			continue;
		}
		const DWORD tid = th32.th32ThreadID;
		auto itr = threads_info.find(tid);
		if (itr == threads_info.end()) {
			threads_info[tid] = thread_info(tid);
		}
	} while (Thread32Next(hThreadSnapShot, &th32));

	CloseHandle(hThreadSnapShot);
	return true;
}
