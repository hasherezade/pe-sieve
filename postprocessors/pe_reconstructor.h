#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include <peconv.h>
#include "../scanners/artefact_scanner.h"
#include "iat_block.h"

class ImportTableBuffer
{
public:
	ImportTableBuffer(DWORD _descriptorsRVA)
		: descriptors(nullptr), descriptosCount(0), 
		descriptorsRVA(_descriptorsRVA),
		namesRVA(0), namesBuf(nullptr), namesBufSize(0)
	{
	}

	~ImportTableBuffer()
	{
		delete[]descriptors;
		delete[]namesBuf;
	}

	bool allocDesciptors(size_t descriptors_count)
	{
		descriptors = new IMAGE_IMPORT_DESCRIPTOR[descriptors_count];
		if (!descriptors) {
			return false;
		}
		memset(descriptors, 0, descriptors_count);
		size_t size_bytes = sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptors_count;
		memset(descriptors, 0, size_bytes);
		descriptosCount = descriptors_count;
		return true;
	}

	bool allocNamesSpace(DWORD names_rva, size_t names_size)
	{
		if (namesBuf) delete[]namesBuf;
		this->namesBuf = new BYTE[names_size];
		if (!this->namesBuf) {
			this->namesBufSize = 0;
			return false;
		}
		memset(this->namesBuf, 0, names_size);
		this->namesBufSize = names_size;
		this->namesRVA = names_rva;
		return true;
	}

	BYTE* getNamesSpaceAt(const DWORD rva, size_t required_size)
	{
		if (!this->namesBuf) return nullptr;
		size_t offset = rva - this->namesRVA;

		BYTE* names_ptr = offset + this->namesBuf;
		if (peconv::validate_ptr(namesBuf, namesBufSize, names_ptr, required_size)) {
			return names_ptr;
		}
		return nullptr;
	}

	size_t getDescriptorsSize()
	{
		if (!descriptors) return 0;
		const size_t size_bytes = sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptosCount;
		return size_bytes;
	}

	size_t getNamesSize()
	{
		if (!this->namesBuf) return 0;
		return this->namesBufSize;
	}

	DWORD getRVA()
	{
		return descriptorsRVA;
	}

protected:
	IMAGE_IMPORT_DESCRIPTOR * descriptors;

private:
	
	DWORD descriptorsRVA;
	size_t descriptosCount;

	DWORD namesRVA;
	BYTE* namesBuf;
	size_t namesBufSize;

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
		: origArtefacts(_artefacts),
		vBuf(nullptr), vBufSize(0), moduleBase(0)
	{
	}

	~PeReconstructor() {
		deleteFoundIATs();
		freeBuffer();
	}

	bool reconstruct(IN HANDLE processHandle);
	bool rebuildImportTable(IN peconv::ExportsMapper* exportsMap, IN const t_pesieve_imprec_mode &imprec_mode);

	bool dumpToFile(IN std::string dumpFileName, IN peconv::t_pe_dump_mode &dumpMode, IN OPTIONAL peconv::ExportsMapper* exportsMap = nullptr);

	void printFoundIATs(std::string reportPath);

protected:
	IATBlock* findIAT(IN peconv::ExportsMapper* exportsMap, size_t start_offset);
	bool findImportTable(IN peconv::ExportsMapper* exportsMap);
	size_t collectIATs(IN peconv::ExportsMapper* exportsMap);

	bool findIATsCoverage(IN peconv::ExportsMapper* exportsMap);
	ImportTableBuffer* constructImportTable();
	bool appendImportTable(ImportTableBuffer &importTable);

	void freeBuffer() {
		peconv::free_aligned(vBuf);
		vBuf = nullptr;
		vBufSize = 0;
		moduleBase = 0;
	}

	bool reconstructFileHdr();
	bool reconstructPeHdr();
	bool fixSectionsVirtualSize(HANDLE processHandle);
	bool fixSectionsCharacteristics(HANDLE processHandle);

	size_t shiftPeHeader();

	bool appendFoundIAT(DWORD iat_offset, IATBlock* found_block)
	{
		if (foundIATs.find(iat_offset) != foundIATs.end()) {
			return false; //already exist
		}
		foundIATs[iat_offset] = found_block;
		return true;
	}

	void deleteFoundIATs()
	{
		std::map<DWORD, IATBlock*>::iterator itr;
		for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
			delete itr->second;
		}
		foundIATs.clear();
	}

	const PeArtefacts origArtefacts;
	PeArtefacts artefacts;
	BYTE *vBuf;
	size_t vBufSize;
	ULONGLONG moduleBase;

	std::map<DWORD, IATBlock*> foundIATs;
};
