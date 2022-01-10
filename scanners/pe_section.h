#pragma once

#include <windows.h>

#include <peconv.h>
#include "module_data.h"

namespace pesieve {

	//! Buffers the defined PE section belonging to the module loaded in the scanned process into the local memory.
	class PeSection
	{
	public:
		PeSection(RemoteModuleData& remoteModData, size_t section_number)
			: loadedSection(nullptr), loadedSize(0), rva(0), rawSize(0)
		{
			loadRemote(remoteModData, section_number);
		}

		PeSection(ModuleData& modData, size_t section_number)
			: loadedSection(nullptr), loadedSize(0), rva(0), rawSize(0)
		{
			loadOriginal(modData, section_number);
		}

		~PeSection()
		{
			unload();
		}

		bool isInitialized()
		{
			return (loadedSection && loadedSize > 0) ? true : false;
		}

		bool isContained(ULONGLONG field_start, size_t field_size)
		{
			ULONGLONG field_end = field_start + field_size;

			bool isInside = (field_start >= this->rva && (field_start < (this->rva + this->loadedSize)))
				|| (field_end >= this->rva && (field_end < (this->rva + this->loadedSize)));

			return isInside;
		}

		size_t rawSize;
		size_t loadedSize;
		PBYTE loadedSection;
		DWORD rva;

	protected:

		bool loadRemote(RemoteModuleData& remoteModData, size_t section_number)
		{
			unload(); //ensure that buffers are empty

			//corner case: if no sections in PE
			const size_t hdr_sec_num = peconv::get_sections_count(remoteModData.headerBuffer, remoteModData.getHeaderSize());
			if (hdr_sec_num == 0 && section_number == 0) {
				return loadRemoteImageAsSection(remoteModData);
			}
			//normal case: if PE has sections
			PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(remoteModData.headerBuffer, peconv::MAX_HEADER_SIZE, section_number);
			if ((!section_hdr) || section_hdr->Misc.VirtualSize == 0) {
				return false;
			}
			this->rawSize = section_hdr->SizeOfRawData;
			this->rva = section_hdr->VirtualAddress;
			//get the code section from the module:
			this->loadedSize = 0;
			this->loadedSection = peconv::get_remote_pe_section(remoteModData.processHandle, (PBYTE)remoteModData.modBaseAddr, section_number, loadedSize, true, remoteModData.isReflection);
			if (loadedSection == nullptr) {
				return false;
			}
			return true;
		}

		bool loadOriginal(ModuleData& modData, size_t section_number)
		{
			unload(); //ensure that buffers are empty

			//corner case: if no sections in PE
			const size_t hdr_sec_num = peconv::get_sections_count(modData.original_module, modData.original_size);
			if (hdr_sec_num == 0 && section_number == 0) {
				return loadOriginalImageAsSection(modData);
			}
			PIMAGE_SECTION_HEADER section_hdr = peconv::get_section_hdr(modData.original_module, modData.original_size, section_number);
			if (section_hdr == nullptr) {
				return false;
			}
			this->rawSize = section_hdr->SizeOfRawData;
			const size_t raw_code_size = section_hdr->SizeOfRawData;
			const size_t orig_code_size = section_hdr->Misc.VirtualSize > raw_code_size ? section_hdr->Misc.VirtualSize : raw_code_size;

			loadedSection = peconv::alloc_unaligned(orig_code_size);
			if (loadedSection == nullptr) {
				return false;
			}
			this->rva = section_hdr->VirtualAddress;
			//make a copy of the section:
			BYTE *orig_code = modData.original_module + section_hdr->VirtualAddress;
			memcpy(loadedSection, orig_code, raw_code_size);
			loadedSize = orig_code_size;
			return true;
		}

		void unload()
		{
			if (!loadedSection) {
				return;
			}
			peconv::free_unaligned(loadedSection);
			loadedSection = nullptr;
			loadedSize = 0;
		}

	private:
		bool loadOriginalImageAsSection(ModuleData& modData)
		{
#ifdef _DEBUG
			std::cout << "PE with no sections! Loading original image as section\n";
#endif
			if (!modData.isInitialized()) {
				return false;
			}
			peconv::UNALIGNED_BUF buf = peconv::alloc_unaligned(modData.original_size);
			if (!buf) {
#ifdef _DEBUG
				std::cout << "Could not alloc: " << std::hex << modData.original_size << "\n";
#endif
				return false;
			}
			memcpy(buf, modData.original_module, modData.original_size);
			loadedSection = buf;
			loadedSize = modData.original_size;
			rawSize = modData.original_size;
			rva = 0;
#ifdef _DEBUG
			std::cout << "Copied local: " << std::hex << modData.original_size << "\n";
#endif
			return true;
		}

		bool _loadRemoteImageAsSection(RemoteModuleData& remoteModData, size_t image_size)
		{
			peconv::UNALIGNED_BUF buf = peconv::alloc_unaligned(image_size);
			if (!buf) {
				return false;
			}
			size_t read_size = peconv::read_remote_pe(remoteModData.processHandle, (PBYTE)remoteModData.modBaseAddr, image_size, buf, image_size);
			if (read_size != image_size) {
				//std::cout << "Read size: " << std::hex << read_size << " vs " << image_size << "\n";
				peconv::free_unaligned(buf);
				return false;
			}
			this->loadedSection = buf;
			this->loadedSize = read_size;
			this->rawSize = 0; // TODO: unknown?
			this->rva = 0;
			return true;
		}

		bool loadRemoteImageAsSection(RemoteModuleData& remoteModData)
		{
#ifdef _DEBUG
			std::cout << "PE with no sections! Loading remote image as section\n";
#endif
			if (_loadRemoteImageAsSection(remoteModData, remoteModData.getModuleSize())) {
				return true;
			}
			// if failed, try again with calculated size
			return _loadRemoteImageAsSection(remoteModData, remoteModData.calcImgSize());
		}
	};

}; //namespace pesieve

