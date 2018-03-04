#pragma once

#include <Windows.h>

#include "peconv.h"
#include "module_data.h"

class PeSection
{
public:
	PeSection(HANDLE processHandle, HMODULE modBaseAddr, size_t section_number)
		: loadedSection(nullptr), loadedSize(0), rva(0)
	{
		is_ready = loadRemote(processHandle, modBaseAddr, section_number);
	}

	PeSection(ModuleData& modData, size_t section_number)
		: loadedSection(nullptr), loadedSize(0)
	{
		is_ready = loadOriginal(modData, section_number);
	}

	~PeSection()
	{
		unload();
	}

	bool isInitialized() 
	{
		return is_ready;
	}

	bool isContained(ULONGLONG field_start, size_t field_size)
	{
		ULONGLONG field_end = field_start + field_size;

		bool isInside = (field_start >= this->rva && (field_start < (this->rva + this->loadedSize)))
			|| (field_end >= this->rva && (field_end < (this->rva + this->loadedSize)));

		return isInside;
	}

	size_t loadedSize;
	PBYTE loadedSection;
	ULONGLONG rva;

protected:

	bool loadRemote(HANDLE processHandle, HMODULE modBaseAddr, size_t section_number)
		{
		//get the code section from the module:
		this->loadedSize = 0;
		this->loadedSection = peconv::get_remote_pe_section(processHandle, (PBYTE) modBaseAddr, section_number, loadedSize);
		if (loadedSection == nullptr) {
			return false;
		}
		return true;
	}

	bool loadOriginal(ModuleData& modData, size_t section_number)
	{
		PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(modData.original_module, modData.original_size, section_number);
		if (section_hdr == nullptr) {
			return false;
		}
		size_t orig_code_size = section_hdr->SizeOfRawData;

		loadedSection = peconv::alloc_pe_section(orig_code_size);
		if (loadedSection == nullptr) {
			return false;
		}

		this->rva = section_hdr->VirtualAddress;

		//make a copy of the section:
		BYTE *orig_code = modData.original_module + section_hdr->VirtualAddress;
		memcpy(loadedSection, orig_code, orig_code_size);
		loadedSize = orig_code_size;
		return true;
	}

	void unload()
	{
		if (!loadedSection) {
			return;
		}
		peconv::free_pe_section(loadedSection);
		loadedSection = nullptr;
		loadedSize = 0;
	}
	
	bool is_ready;
};
