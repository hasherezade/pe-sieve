#include "workingset_enum.h"

#include <iostream>

namespace pesieve {
	namespace util {

		bool get_next_commited_region(HANDLE processHandle, ULONGLONG start_va, MEMORY_BASIC_INFORMATION &page_info)
		{
			while (true) {
				//std::cout << "Checking: " << std::hex << start_va << " vs " << std::hex << max_va << std::endl;
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
				if (error == ERROR_BAD_LENGTH) {
#ifdef _DEBUG
					if (sizeof(page_info) != sizeof(MEMORY_BASIC_INFORMATION64)){
						std::cerr << "[WARNING] Use 64-bit scanner. Error:" << std::dec << error << std::endl;
					}
#endif
					break;
				}
				if (out != sizeof(page_info) || error != ERROR_SUCCESS) {
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
#ifdef _WIN64
	ULONGLONG mask = ULONGLONG(-1);
#else
	ULONGLONG mask = DWORD(-1);
#endif

	region_bases.clear();

	MEMORY_BASIC_INFORMATION page_info = { 0 };
	ULONGLONG next_va = 0;
	while (get_next_commited_region(processHandle, next_va, page_info))
	{
		ULONGLONG base = (ULONGLONG)page_info.BaseAddress & mask;
		next_va = base + page_info.RegionSize; //end of the region
		if (region_bases.find(base) != region_bases.end()) {
			// don't let it stuck on adding the same region over and over again
			break;
		}
		region_bases.insert(base);
	}
	return region_bases.size();
}
