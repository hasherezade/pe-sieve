#pragma once

#include <Windows.h>
#include <peconv.h>
#include <iostream>

template <typename FIELD_T>
BYTE* find_iat(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, size_t search_offset)
{
	if (!vBuf || !exportsMap) return nullptr;
	if (search_offset > vBufSize || (vBufSize - search_offset) < sizeof(FIELD_T)) {
		return nullptr; //size check failed
	}
	size_t max_check = vBufSize - sizeof(FIELD_T);
	for (BYTE* ptr = vBuf; ptr < vBuf + max_check; ptr++) {
		FIELD_T *to_check = (FIELD_T*)ptr;
		if (!peconv::validate_ptr(vBuf, vBufSize, to_check, sizeof(FIELD_T))) break;
		FIELD_T possible_rva = (*to_check);
		if (possible_rva == 0) continue;
		//std::cout << "checking: " << std::hex << possible_rva << std::endl;
		const peconv::ExportedFunc *exp = exportsMap->find_export_by_va(possible_rva);
		if (!exp) continue;

		//validate IAT:
		ULONGLONG offset = (ptr - vBuf);
		std::cout << std::hex << offset << " : " << exp->funcName << std::endl;

		BYTE *iat_ptr = ptr;
		size_t imports = 0;
		for (FIELD_T* imp = to_check; imp < (FIELD_T*)(vBuf + max_check); imp++) {
			if (*imp == 0) continue;
			exp = exportsMap->find_export_by_va(*imp);
			if (!exp) break;

			ULONGLONG offset = ((BYTE*)imp - vBuf);
			std::cout << std::hex << offset << " : " << exp->funcName << std::endl;
			imports++;
		}
		if (!exp && iat_ptr && imports > 2) {
			return iat_ptr;
		}
	}
	return nullptr;
}

IMAGE_IMPORT_DESCRIPTOR* find_import_table(BYTE* vBuf, size_t vBufSize, DWORD iat_offset, size_t search_offset = 0);
