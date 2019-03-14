#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "../scanners/artefact_scanner.h"


template <typename IMAGE_OPTIONAL_HEADER_T>
bool overwrite_opt_hdr(BYTE* vBuf, size_t vBufSize, IMAGE_OPTIONAL_HEADER_T* opt_hdr_ptr, PeArtefacts &artefacts)
{
	std::cout << "Trying to overwrite the optional header\n";
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

	if (opt_hdr_ptr->SectionAlignment > PAGE_SIZE) {
		opt_hdr_ptr->SectionAlignment = PAGE_SIZE;
	}
	if (opt_hdr_ptr->FileAlignment > PAGE_SIZE) {
		opt_hdr_ptr->FileAlignment = 0x200; // typical file alignment
	}
	if (opt_hdr_ptr->SizeOfHeaders > PAGE_SIZE) {
		opt_hdr_ptr->SizeOfHeaders = 0x400; //typical header size
	}
	opt_hdr_ptr->SizeOfImage = artefacts.calculatedImgSize;
	return true;
}

class PeReconstructor {
public:
	PeReconstructor(PeArtefacts _artefacts, peconv::t_pe_dump_mode &dump_mode)
		: artefacts(_artefacts),
		vBuf(nullptr), vBufSize(0), moduleBase(0), dumpMode(dump_mode)
	{
	}

	~PeReconstructor() {
		freeBuffer();
	}

	bool reconstruct(IN HANDLE processHandle, IN OPTIONAL peconv::ExportsMapper* exportsMap = nullptr);
	bool dumpToFile(IN std::string dumpFileName, IN OPTIONAL peconv::ExportsMapper* exportsMap = nullptr);

protected:
	bool findIAT(IN peconv::ExportsMapper* exportsMap);
	bool findImportTable(IN peconv::ExportsMapper* exportsMap);

	void freeBuffer() {
		peconv::free_aligned(vBuf);
		vBuf = nullptr;
		vBufSize = 0;
		moduleBase = 0;
	}

	bool reconstructFileHdr();
	bool reconstructPeHdr();
	bool reconstructSectionsHdr(HANDLE processHandle);

	size_t shiftPeHeader();

	PeArtefacts artefacts;
	BYTE *vBuf;
	size_t vBufSize;
	ULONGLONG moduleBase;

	peconv::t_pe_dump_mode &dumpMode;
};
