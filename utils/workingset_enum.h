#pragma once

#include <windows.h>
#include <set>

#ifdef _DEBUG
#include <iostream>
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

namespace pesieve {
	namespace util {

		typedef struct _mem_region_info
		{
			ULONGLONG alloc_base;
			ULONGLONG base;
			size_t size;

			_mem_region_info()
				: alloc_base(0), base(0),  size(0)
			{
			}

			_mem_region_info(ULONGLONG _alloc_base, ULONGLONG _base, size_t _size)
				: alloc_base(_alloc_base), base(_base), size(_size)
			{
			}

			_mem_region_info(const _mem_region_info& other)
			{
				this->base = other.base;
				this->alloc_base = other.alloc_base;
				this->size = other.size;
			}

			bool operator<(const _mem_region_info& rhs) const
			{
				return this->base < rhs.base;
			}

#ifdef _DEBUG
			void print() const
			{
				std::cout << "Region:\t" << std::hex << this->alloc_base << " :\t";
				if (this->alloc_base != this->base) {
					std::cout << this->base << " :\t";
				}
				else {
					std::cout << "*" << " :\t";
				}
				std::cout << this->size << std::endl;
			}
#endif

		} mem_region_info;

		size_t enum_workingset(HANDLE processHandle, std::set<mem_region_info> &regions);

		DWORD count_workingset_entries(HANDLE processHandle);
	};
};
