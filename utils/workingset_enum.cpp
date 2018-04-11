#include "workingset_enum.h"

#include <iostream>

const ULONGLONG MAX_32BIT = 0x07FFFFFFF;
const ULONGLONG MAX_64BIT = 0x07FFFFFFFFFF;

bool get_next_region(HANDLE processHandle, ULONGLONG start_va, ULONGLONG max_va, MEMORY_BASIC_INFORMATION &page_info)
{
	for (; start_va < max_va; start_va += PAGE_SIZE) {
		//std::cout << "Checking: " << std::hex << start_va << " vs " << std::hex << max_va << std::endl;
		SIZE_T out = VirtualQueryEx(processHandle, (LPCVOID) start_va, &page_info, sizeof(page_info));
		if (out != sizeof(page_info)) {
			const DWORD error = GetLastError();
			if (error == ERROR_INVALID_PARAMETER) {
				break;
			}
			std::cerr << "Error:" << std::hex << error << std::endl;
			continue;
		}
		if (page_info.RegionSize == 0) {
			continue;
		}
		return true;
	}
	return false;
}

size_t enum_workingset(HANDLE processHandle, std::set<ULONGLONG> &region_bases)
{

#ifdef _WIN64
	ULONGLONG max_addr = MAX_64BIT;
#else
	ULONGLONG max_addr = MAX_32BIT;
#endif

	size_t added = 0;
	for (ULONGLONG next_va = 0; next_va <= max_addr; )
	{
		MEMORY_BASIC_INFORMATION page_info = { 0 };
		if (!get_next_region(processHandle, next_va, max_addr, page_info)) {
			break;
		}
		//std::cout << "Got addr: " << std::hex << page_info.BaseAddress << std::endl;
		
		ULONGLONG base = (ULONGLONG) page_info.BaseAddress;
		next_va = base + page_info.RegionSize; //end of the region

		if (page_info.State & MEM_FREE) continue;

		if ((page_info.State & MEM_COMMIT) == 0) {
			//skip pages that are not commited
			continue;
		}
		region_bases.insert(base);
		added++;
	}
	return added;
}

bool read_remote_mem(HANDLE processHandle, BYTE *start_addr, OUT BYTE* buffer, const size_t buffer_size)
{
	if (buffer == nullptr) return false;

	SIZE_T read_size = 0;
	const SIZE_T step_size = 0x100;
	SIZE_T to_read_size = buffer_size;
	memset(buffer, 0, buffer_size);
	while (to_read_size >= step_size) {
		BOOL is_ok = ReadProcessMemory(processHandle, start_addr, buffer, to_read_size, &read_size);
		if (!is_ok) {
			//try to read less
			to_read_size -= step_size;
			continue;
		}
		return true;
	}
	return false;
}
