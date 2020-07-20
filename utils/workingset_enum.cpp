#include "workingset_enum.h"

#include <iostream>

#ifdef _WIN64
	const ULONGLONG mask = ULONGLONG(-1);
#else
	const ULONGLONG mask = DWORD(-1);
#endif

namespace pesieve {
	namespace util {

		bool get_next_commited_region(HANDLE processHandle, ULONGLONG start_va, MEMORY_BASIC_INFORMATION &page_info)
		{
			while (start_va < mask) {
				//std::cout << "Checking: " << std::hex << start_va << std::endl;
				memset(&page_info, 0, sizeof(MEMORY_BASIC_INFORMATION));
				SIZE_T out = VirtualQueryEx(processHandle, (LPCVOID)start_va, &page_info, sizeof(page_info));
				const DWORD error = GetLastError();
				if (error == ERROR_INVALID_PARAMETER) {
					//nothing more to read
#ifdef _DEBUG
					std::cout << "Nothing more to read: " << std::hex << start_va << std::endl;
#endif
					break;
				}
				if (error == ERROR_ACCESS_DENIED) {
					std::cerr << "[WARNING] Cannot query the memory region. Error: " << std::dec << error << std::endl;
					break;
				}
				/*
				Allow to proceed on ERROR_BAD_LENGTH, if the filled MEMORY_BASIC_INFORMATION is as expected.
				(ERROR_BAD_LENGTH may occur if the scanner is 32 bit and running on a 64 bit system.)
				Otherwise - also on different error - skip.
				*/
				if (out != sizeof(page_info) || error != ERROR_BAD_LENGTH) {
					std::cerr << "[WARNING] Cannot query the memory region. Error: " << std::dec << error << std::endl;
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
				//std::cout << "Commited:  " << std::hex << start_va << " RegionSize: " << page_info.RegionSize << std::endl;
				return true;
			}
			return false;
		}

	};
};

size_t pesieve::util::enum_workingset(HANDLE processHandle, std::set<ULONGLONG> &region_bases)
{
	region_bases.clear();

	MEMORY_BASIC_INFORMATION page_info = { 0 };
	ULONGLONG next_va = 0;
	while (get_next_commited_region(processHandle, next_va, page_info))
	{
		ULONGLONG base = (ULONGLONG)page_info.BaseAddress;
		next_va = base + page_info.RegionSize; //end of the region
		if (region_bases.find(base) != region_bases.end()) {
			// don't let it stuck on adding the same region over and over again
			break;
		}
		region_bases.insert(base);
	}
	return region_bases.size();
}
