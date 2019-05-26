#pragma once 

#include <peconv.h>

#include <sstream>
#include <map>

class IATBlock
{
public:
	IATBlock(BYTE* _vBuf, size_t _vBufSize, BYTE* _iat_ptr)
		: vBuf(_vBuf), vBufSize(_vBufSize),
		iat_ptr(_iat_ptr), iat_size(0), isValid(false), isMain(false),
		importTable(nullptr)
	{
	}


	bool append(ULONGLONG offset, const peconv::ExportedFunc *exp)
	{
		if (!exp) return false;

		functions[offset] = exp;
		return true;
	}

	std::string toString()
	{
		std::stringstream stream;
		stream << "---\nIAT at: " << std::hex << getOffset(iat_ptr) << " size: " << iat_size << "\n";
		if (this->importTable) {
			stream << "---\nImportTable: " << std::hex << getOffset(importTable) << "\n";
		}
		std::map<ULONGLONG, const peconv::ExportedFunc*>::const_iterator itr;
		for (itr = functions.begin(); itr != functions.end(); itr++) {
			ULONGLONG offset = itr->first;
			const peconv::ExportedFunc* exp = itr->second;
			
			stream << std::hex << offset << "," << exp->toString() << "\n";
		}
		return stream.str();
	}

	bool isValid;
	bool isMain;

	BYTE* iat_ptr;
	size_t iat_size;
	IMAGE_IMPORT_DESCRIPTOR* importTable;

protected:
	DWORD getOffset(void* ptr)
	{
		if (!peconv::validate_ptr(vBuf, vBufSize, ptr, sizeof(DWORD))) {
			return 0;
		}
		return DWORD((ULONG_PTR)ptr - (ULONG_PTR)vBuf);
	}

	BYTE* vBuf;
	size_t vBufSize;

	std::map<ULONGLONG, const peconv::ExportedFunc*> functions;
};
