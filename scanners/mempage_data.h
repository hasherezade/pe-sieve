#pragma once

#include <windows.h>

#include <peconv.h>

namespace pesieve {

	class MemPageData
	{
	public:
		MemPageData(HANDLE _process, ULONGLONG _start_va, ULONGLONG _stop_va = 0)
			: processHandle(_process), start_va(_start_va), stop_va(_stop_va),
			is_listed_module(false),
			is_info_filled(false), loadedData(nullptr), loadedSize(0),
			is_dep_enabled(false)
		{
			fillInfo();
		}

		virtual ~MemPageData()
		{
			_freeRemote();
		}

		bool fillInfo();
		bool isInfoFilled() { return is_info_filled; }
		size_t getLoadedSize() { return loadedSize; }
		const PBYTE getLoadedData() { return loadedData; }

		bool validatePtr(const LPVOID field_bgn, size_t field_size)
		{
			return peconv::validate_ptr(this->loadedData, this->loadedSize, field_bgn, field_size);
		}

		ULONGLONG start_va; // VA that was requested. May not be beginning of the region.
		ULONGLONG stop_va; // maximum VA that will be read
		DWORD protection;
		DWORD initial_protect;
		bool is_private;
		DWORD mapping_type;
		bool is_listed_module;
		bool is_dep_enabled;

		ULONGLONG alloc_base;
		ULONGLONG region_start;
		ULONGLONG region_end;

		std::string mapped_name; //if the region is mapped from a file
		std::string module_name; //if the region is on the list of loaded PEs

		bool load()
		{
			if (loadedData) {
				return true;
			}
			if (!_loadRemote()) {
				return false;
			}
			//check again:
			if (loadedData) {
				return true;
			}
			return false;
		}

		bool loadMappedName();
		bool loadModuleName();
		// checks if the memory area is mapped 1-to-1 from the file on the disk
		bool isRealMapping();

	protected:
		bool _loadRemote();

		void _freeRemote()
		{
			if (!loadedData) {
				return;
			}
			peconv::free_aligned(loadedData, loadedSize);
			loadedData = nullptr;
			loadedSize = 0;
		}

		PBYTE loadedData;
		size_t loadedSize;

		bool is_info_filled;
		HANDLE processHandle;
	};

}; //namespace pesieve

