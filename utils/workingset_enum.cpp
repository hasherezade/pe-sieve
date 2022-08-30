#include "workingset_enum.h"

#include <iostream>

#include <psapi.h>
#pragma comment(lib,"psapi.lib")

#ifdef _WIN64
	const ULONGLONG mask = ULONGLONG(-1);
#else
	const ULONGLONG mask = DWORD(-1);
#endif

namespace pesieve {
	namespace util {

		bool get_next_commited_region(HANDLE processHandle, ULONGLONG start_va, MEMORY_BASIC_INFORMATION &page_info)
		{
			const SIZE_T page_info_size = sizeof(MEMORY_BASIC_INFORMATION);

			while (start_va < mask) {
				//std::cout << "Checking: " << std::hex << start_va << std::endl;
				memset(&page_info, 0, page_info_size);
				const SIZE_T out = VirtualQueryEx(processHandle, (LPCVOID)start_va, &page_info, page_info_size);
				const bool is_read = (out == page_info_size) ? true : false;
				const DWORD error = is_read ? ERROR_SUCCESS : GetLastError();
				if (error == ERROR_INVALID_PARAMETER) {
					//nothing more to read
#ifdef _DEBUG
					std::cout << "Nothing more to read: " << std::hex << start_va << std::endl;
#endif
					break;
				}
				if (error == ERROR_ACCESS_DENIED) {
					std::cerr << "[ERROR] Cannot query the memory region. " << std::hex << start_va << " Error: " << std::dec << error << std::endl;
					break;
				}
				if (!is_read) {
					// on any other error:
					std::cerr << "[WARNING] Cannot query the memory region. " << std::hex<< start_va << " Error: " << std::dec << error << ", skipping the page..." << std::endl;
					start_va += PAGE_SIZE;
					continue;
				}
				if ((page_info.State & MEM_FREE) || (page_info.State & MEM_COMMIT) == 0) {
					if (page_info.RegionSize != 0) {
						//std::cout << "Free:  " << std::hex << start_va << " RegionSize:" << page_info.RegionSize << std::endl;
						start_va += page_info.RegionSize;
						continue;
					}
				}
				if (page_info.RegionSize == 0) {
					start_va += PAGE_SIZE;
					continue;
				}
				//std::cout << "Commited:  " << std::hex << start_va << " RegionSize: " << page_info.RegionSize << " Err: " << std::dec << error << std::endl;
				return true;
			}
			return false;
		}

	};
};

size_t pesieve::util::enum_workingset(HANDLE processHandle, std::set<mem_region_info> &region_bases)
{
	region_bases.clear();

	MEMORY_BASIC_INFORMATION page_info = { 0 };
	ULONGLONG next_va = 0;
	while (get_next_commited_region(processHandle, next_va, page_info))
	{
		ULONGLONG base = (ULONGLONG)page_info.BaseAddress;
		next_va = base + page_info.RegionSize; //end of the region
		mem_region_info curr_info((ULONGLONG)page_info.AllocationBase, base, page_info.RegionSize);

		if (region_bases.find(curr_info) != region_bases.end()) {
			// don't let it stuck on adding the same region over and over again
			break;
		}
		region_bases.insert(curr_info);
	}
	return region_bases.size();
}

DWORD pesieve::util::count_workingset_entries(HANDLE processHandle)
{
	DWORD number_of_entries = 1;
	DWORD buffer_size = sizeof(PSAPI_WORKING_SET_INFORMATION) + (number_of_entries * sizeof(PSAPI_WORKING_SET_BLOCK));
	PSAPI_WORKING_SET_INFORMATION* buffer = reinterpret_cast<PSAPI_WORKING_SET_INFORMATION*>(calloc(1, buffer_size));
	if (!buffer) {
		return 0; //this should not happen
	}
	DWORD res = QueryWorkingSet(processHandle, buffer, buffer_size);
	if (res == FALSE && GetLastError() == ERROR_BAD_LENGTH) {
		// ERROR_BAD_LENGTH is normal: we didn't provide the buffer that could fit all the entries
		res = TRUE;
	}
	number_of_entries = static_cast<DWORD>(buffer->NumberOfEntries);
	free(buffer); buffer = NULL;

	if (!res) {
		return 0;
	}
#ifdef _DEBUG
	std::cout << "Number of entries: " << std::dec << number_of_entries << std::endl;
#endif
	return number_of_entries;
}
