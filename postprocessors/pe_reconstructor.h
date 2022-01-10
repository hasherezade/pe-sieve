#pragma once

#include <windows.h>
#include <psapi.h>
#include <map>
#include <peconv.h>

#include "pe_buffer.h"
#include "../scanners/artefact_scanner.h"

namespace pesieve {

	template <typename IMAGE_OPTIONAL_HEADER_T>
	bool overwrite_opt_hdr(BYTE* vBuf, size_t vBufSize, IMAGE_OPTIONAL_HEADER_T* opt_hdr_ptr, PeArtefacts &artefacts)
	{
#ifdef _DEBUG
		std::cout << "Trying to overwrite the optional header\n";
#endif
		if (!vBuf || !opt_hdr_ptr) return false;
		if (!peconv::validate_ptr(vBuf, vBufSize, opt_hdr_ptr, sizeof(IMAGE_OPTIONAL_HEADER_T))) {
			return false;
		}
		if (artefacts.is64bit) {
			opt_hdr_ptr->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		}
		else {
			opt_hdr_ptr->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		}
		//set typical values for the fields that has been erased:
		if (opt_hdr_ptr->SectionAlignment == 0) {
			opt_hdr_ptr->SectionAlignment = PAGE_SIZE;
		}
		if (opt_hdr_ptr->FileAlignment == 0) {
			opt_hdr_ptr->FileAlignment = 0x200; // typical file alignment
		}
		if (opt_hdr_ptr->SizeOfHeaders == 0) {
			opt_hdr_ptr->SizeOfHeaders = 0x400; //typical header size
		}
		if (opt_hdr_ptr->SizeOfImage < artefacts.calculatedImgSize) {
			opt_hdr_ptr->SizeOfImage = MASK_TO_DWORD(artefacts.calculatedImgSize);
		}
		return true;
	}

	class PeReconstructor {
	public:
		PeReconstructor(PeArtefacts _artefacts, PeBuffer &_peBuffer)
			: origArtefacts(_artefacts), peBuffer(_peBuffer)
		{
		}

		bool reconstruct();

	protected:
		bool reconstructFileHdr();
		bool reconstructPeHdr();
		bool fixSectionsVirtualSize(HANDLE processHandle);
		bool fixSectionsCharacteristics(HANDLE processHandle);

		size_t shiftPeHeader();

		const PeArtefacts origArtefacts;
		PeArtefacts artefacts;
		PeBuffer &peBuffer;
	};

}; //mamespace pesieve

