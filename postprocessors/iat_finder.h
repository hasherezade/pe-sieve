#pragma once

#include <Windows.h>
#include <peconv.h>
#include <iostream>

template <typename FIELD_T>
size_t calc_iat_size(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, FIELD_T* iat_ptr)
{
	if (!vBuf || !exportsMap || !iat_ptr) return 0;

	size_t max_check = vBufSize - sizeof(FIELD_T);
	if (max_check < sizeof(FIELD_T)) {
		return 0; //size check failed
	}
	
	size_t imports = 0;
	const peconv::ExportedFunc *exp = nullptr;

	FIELD_T *imp = (FIELD_T*)iat_ptr;
	for (; imp < (FIELD_T*)(vBuf + max_check); imp++) {
		if (*imp == 0) continue;
		exp = exportsMap->find_export_by_va(*imp);
		if (!exp) break;

		ULONGLONG offset = ((BYTE*)imp - vBuf);
		std::cout << std::hex << offset << " : " << exp->funcName << std::endl;
		imports++;
	}
	if (!exp && iat_ptr && imports > 1) {
		size_t diff = (BYTE*)imp - (BYTE*)iat_ptr;
		return diff;
	}
	return 0; // invalid IAT
}

template <typename FIELD_T>
BYTE* find_iat(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, IN OUT size_t &iat_size, IN OPTIONAL size_t search_offset = 0)
{
	iat_size = 0;
	if (!vBuf || !exportsMap) return nullptr;

	size_t max_check = vBufSize - sizeof(FIELD_T);
	if (search_offset > vBufSize || max_check < sizeof(FIELD_T)) {
		return nullptr; //size check failed
	}
	
	for (BYTE* ptr = vBuf; ptr < vBuf + max_check; ptr++) {
		FIELD_T *to_check = (FIELD_T*)ptr;
		if (!peconv::validate_ptr(vBuf, vBufSize, to_check, sizeof(FIELD_T))) break;
		FIELD_T possible_rva = (*to_check);
		if (possible_rva == 0) continue;
		//std::cout << "checking: " << std::hex << possible_rva << std::endl;
		const peconv::ExportedFunc *exp = exportsMap->find_export_by_va(possible_rva);
		if (!exp) continue;

		//validate IAT:
		size_t _iat_size = calc_iat_size<FIELD_T>(vBuf, vBufSize, exportsMap, to_check);
		if (_iat_size > 0) {
			iat_size = _iat_size;
			return (BYTE*)to_check;
		}
	}
	return nullptr;
}

IMAGE_IMPORT_DESCRIPTOR* find_import_table(BYTE* vBuf, size_t vBufSize, DWORD iat_offset, size_t search_offset = 0);
