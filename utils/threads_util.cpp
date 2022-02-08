#include "threads_util.h"

#include <peconv.h>
#include <tlhelp32.h>
#include "../utils/ntddk.h"

#ifdef _DEBUG
#include <iostream>
#endif

bool pesieve::util::fetch_threads_info(DWORD pid, std::vector<thread_info>& threads_info)
{
	BYTE* buffer = nullptr;
	ULONG buffer_size = 0;
	ULONG ret_len = 0;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	while (status != STATUS_SUCCESS) {
		status = NtQuerySystemInformation(SystemProcessInformation, buffer, buffer_size, &ret_len);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			free(buffer);
			buffer = nullptr;
			buffer_size = 0;
			buffer = (BYTE*)calloc(ret_len, 1);
			if (!buffer) {
				return false;
			}
			buffer_size = ret_len;
			continue; // try again
		}
		break; //other error, or success
	};

	if (status != STATUS_SUCCESS) {
		free(buffer);
		return false;
	}

	bool found = false;
	SYSTEM_PROCESS_INFORMATION* info = (SYSTEM_PROCESS_INFORMATION*)buffer;
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
		if (!peconv::validate_ptr(buffer, buffer_size, info, sizeof(SYSTEM_PROCESS_INFORMATION))) {
			break;
		}
	}

	if (!found) {
		free(buffer);
		return false;
	}

	size_t thread_count = info->NumberOfThreads;
	for (size_t i = 0; i < thread_count; i++) {
		thread_info threadi;

		threadi.tid = MASK_TO_DWORD((ULONGLONG)info->Threads[i].ClientId.UniqueThread);
		threadi.is_extended = true;
		threadi.ext.start_addr = (ULONG_PTR)info->Threads[i].StartAddress;
		threadi.ext.state = info->Threads[i].ThreadState;
		threadi.ext.wait_reason = info->Threads[i].WaitReason;
		threadi.ext.wait_time  = info->Threads[i].WaitTime;
		threads_info.push_back(threadi);
	}

	free(buffer);
	return true;
}

bool pesieve::util::fetch_threads_by_snapshot(DWORD pid, std::vector<thread_info>& threads_info)
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

		thread_info threadi;
		threadi.tid = th32.th32ThreadID;
		threadi.is_extended = false;
		threads_info.push_back(threadi);

	} while (Thread32Next(hThreadSnapShot, &th32));

	CloseHandle(hThreadSnapShot);
	return true;
}
