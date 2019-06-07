#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include <peconv.h>
#include "../scanners/artefact_scanner.h"

class PeBuffer {
public:
	PeBuffer()
		: vBuf(nullptr), vBufSize(0), moduleBase(0)
	{
	}

	~PeBuffer()
	{
		freeBuffer();
	}

	bool allocBuffer(const size_t pe_vsize)
	{
		freeBuffer();
		vBuf = peconv::alloc_aligned(pe_vsize, PAGE_READWRITE);
		if (!vBuf) {
			return false;
		}
		vBufSize = pe_vsize;
		return true;
	}

	void freeBuffer()
	{
		peconv::free_aligned(vBuf);
		vBuf = nullptr;
		vBufSize = 0;
		moduleBase = 0;
	}

	bool readRemote(HANDLE process_hndl, ULONGLONG module_base, size_t pe_vsize)
	{
		if (!allocBuffer(pe_vsize)) {
			return false;
		}
		size_t read_size = peconv::read_remote_area(process_hndl, (BYTE*)module_base, vBuf, pe_vsize);
		if (read_size == 0) {
			freeBuffer();
			return false;
		}
		this->moduleBase = module_base;
		return true;
	}
	
	bool resizeBuffer(size_t new_size)
	{
		BYTE *new_buf = peconv::alloc_aligned(new_size, PAGE_READWRITE);
		if (!new_buf) {
			return false;
		}
		size_t smaller_size = (vBufSize < new_size) ? vBufSize : new_size;
		memcpy(new_buf, this->vBuf, smaller_size);
		freeBuffer();

		this->vBuf = new_buf;
		this->vBufSize = new_size;
		return true;
	}

protected:
	BYTE *vBuf;
	size_t vBufSize;
	ULONGLONG moduleBase;

	friend class ImpReconstructor;
	friend class PeReconstructor;
};

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

	if (opt_hdr_ptr->SectionAlignment > PAGE_SIZE) {
		opt_hdr_ptr->SectionAlignment = PAGE_SIZE;
	}
	if (opt_hdr_ptr->FileAlignment > PAGE_SIZE) {
		opt_hdr_ptr->FileAlignment = 0x200; // typical file alignment
	}
	if (opt_hdr_ptr->SizeOfHeaders > PAGE_SIZE) {
		opt_hdr_ptr->SizeOfHeaders = 0x400; //typical header size
	}
	if (opt_hdr_ptr->SizeOfImage < artefacts.calculatedImgSize) {
		opt_hdr_ptr->SizeOfImage = artefacts.calculatedImgSize;
	}
	return true;
}

class PeReconstructor {
public:
	PeReconstructor(PeArtefacts _artefacts)
		: origArtefacts(_artefacts)
	{
		this->peBuffer = new PeBuffer();
	}

	~PeReconstructor() {
		delete peBuffer;
	}
	
	//WARNING: the buffer will be deleted when the PeReconstructor is deleted
	PeBuffer* getBuffer()
	{
		return this->peBuffer;
	}

	bool reconstruct(IN HANDLE processHandle);
	bool dumpToFile(IN std::string dumpFileName, IN peconv::t_pe_dump_mode &dumpMode, IN OPTIONAL peconv::ExportsMapper* exportsMap = nullptr);

protected:
	bool reconstructFileHdr();
	bool reconstructPeHdr();
	bool fixSectionsVirtualSize(HANDLE processHandle);
	bool fixSectionsCharacteristics(HANDLE processHandle);

	size_t shiftPeHeader();

	const PeArtefacts origArtefacts;
	PeArtefacts artefacts;
	PeBuffer *peBuffer;
};
