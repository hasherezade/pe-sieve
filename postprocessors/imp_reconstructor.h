#pragma once

#include <Windows.h>
#include <map>

#include <peconv.h>

#include "pe_reconstructor.h"
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

	friend class ImpReconstructor;
};

class ImpReconstructor {
public:
	ImpReconstructor(PeBuffer *_peBuffer) 
	: peBuffer(_peBuffer), is64bit(false)
	{
		if (_peBuffer && _peBuffer->vBuf) {
			this->is64bit = peconv::is64bit(_peBuffer->vBuf);
		}
	}

	~ImpReconstructor()
	{
		deleteFoundIATs();
	}

	bool rebuildImportTable(IN peconv::ExportsMapper* exportsMap, IN const t_pesieve_imprec_mode &imprec_mode);

	IATBlock* findIAT(IN peconv::ExportsMapper* exportsMap, size_t start_offset);
	bool findImportTable(IN peconv::ExportsMapper* exportsMap);
	size_t collectIATs(IN peconv::ExportsMapper* exportsMap);

	bool findIATsCoverage(IN peconv::ExportsMapper* exportsMap);
	ImportTableBuffer* constructImportTable();
	bool appendImportTable(ImportTableBuffer &importTable);

	void printFoundIATs(std::string reportPath);

	bool appendFoundIAT(DWORD iat_offset, IATBlock* found_block)
	{
		if (foundIATs.find(iat_offset) != foundIATs.end()) {
			return false; //already exist
		}
		foundIATs[iat_offset] = found_block;
		return true;
	}

protected:

	void deleteFoundIATs()
	{
		std::map<DWORD, IATBlock*>::iterator itr;
		for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
			delete itr->second;
		}
		foundIATs.clear();
	}

	PeBuffer *peBuffer;
	bool is64bit;
	std::map<DWORD, IATBlock*> foundIATs;
};
