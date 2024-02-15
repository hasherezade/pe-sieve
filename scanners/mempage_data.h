#pragma once

#include <windows.h>

#include <peconv.h>

#include "../utils/byte_buffer.h"

namespace pesieve {

	class MemPageData
	{
	public:
		MemPageData(HANDLE _process, bool _is_process_refl, ULONGLONG _start_va, ULONGLONG _stop_va)
			: processHandle(_process), start_va(_start_va), stop_va(_stop_va),
			is_listed_module(false),
			is_info_filled(false),
			is_process_refl(_is_process_refl)
		{
			fillInfo();
		}

		virtual ~MemPageData()
		{
			_freeRemote();
		}

		bool isRefl() const { return is_process_refl; }
		bool fillInfo();
		bool isInfoFilled() { return is_info_filled; }
		size_t getLoadedSize(bool trimmed = false) { return loadedData.getDataSize(trimmed); }
		const PBYTE getLoadedData(bool trimmed = false) { return (PBYTE)loadedData.getData(trimmed); }
		const size_t getStartOffset(bool trimmed = false) { return loadedData.getStartOffset(trimmed); }

		bool validatePtr(const LPVOID field_bgn, size_t field_size)
		{
			return loadedData.isValidPtr((BYTE*)field_bgn, field_size);
		}

		ULONGLONG start_va; ///< VA that was requested. May not be beginning of the region.
		ULONGLONG stop_va; ///< the VA at which the read will stop
		DWORD protection; ///< page protection
		DWORD initial_protect;
		bool is_private;
		DWORD mapping_type;
		bool is_listed_module;

		ULONGLONG alloc_base;
		ULONGLONG region_start;
		ULONGLONG region_end;

		std::string mapped_name; ///< if the region is mapped from a file, stores its file name
		std::string module_name; ///< if the region is on the list of loaded PEs, stores its module name

		// Checks if `loadedData` is already filled, if not, fills it by reading the remote memory.
		bool load()
		{
			if (loadedData.isFilled()) {
				return true;
			}
			if (!_loadRemote()) {
				return false;
			}
			//check again:
			if (loadedData.isFilled()) {
				return true;
			}
			return false;
		}

		bool loadMappedName();
		bool loadModuleName();

		// checks if the memory area is mapped 1-to-1 from the file on the disk
		bool isRealMapping();

		util::ByteBuffer loadedData;

	protected:
		bool _loadRemote();

		void _freeRemote()
		{
			loadedData.freeBuffer();
		}

		bool is_info_filled;
		const bool is_process_refl;
		HANDLE processHandle;
	};

}; //namespace pesieve

