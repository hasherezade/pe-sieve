#pragma once

#include <Windows.h>
#include <peconv.h>

#include "iat_block.h"

IATBlock* find_iat_block(
	IN bool is64bit,
	IN BYTE* vBuf,
	IN size_t vBufSize,
	IN peconv::ExportsMapper* exportsMap,
	IN OPTIONAL size_t search_offset
);

template <typename FIELD_T>
size_t fill_iat(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, IN OUT IATBlock &iat)
{
	if (!vBuf || !exportsMap || !iat.iat_ptr) return 0;

	size_t max_check = vBufSize - sizeof(FIELD_T);
	if (max_check < sizeof(FIELD_T)) {
		return 0; //size check failed
	}

	iat.thunksCount = 0;
	iat.isTerminated = false;
	const peconv::ExportedFunc *exp = nullptr;

	bool is_terminated = false;
	FIELD_T *imp = (FIELD_T*)iat.iat_ptr;
	for (; imp < (FIELD_T*)(vBuf + max_check); imp++) {
		if (*imp == 0) {
			is_terminated = true;
			continue;
		}
		exp = exportsMap->find_export_by_va(*imp);
		if (!exp) break;

		is_terminated = false;
		ULONGLONG offset = ((BYTE*)imp - vBuf);
		iat.append(offset, exp);
		iat.thunksCount++;
	}
	iat.isTerminated = is_terminated;
	if (!exp && iat.iat_ptr && iat.thunksCount > 0) {
		size_t diff = (BYTE*)imp - (BYTE*)iat.iat_ptr;
		iat.iat_size = diff;
		return iat.iat_size;
	}
	return 0; // invalid IAT
}

template <typename FIELD_T>
IATBlock* find_iat(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, IN OPTIONAL size_t search_offset = 0)
{
	if (!vBuf || !exportsMap) return nullptr;

	size_t max_check = vBufSize - sizeof(FIELD_T);
	if (search_offset > vBufSize || max_check < sizeof(FIELD_T)) {
		return nullptr; //size check failed
	}
	
	for (BYTE* ptr = vBuf + search_offset; ptr < vBuf + max_check; ptr++) {
		FIELD_T *to_check = (FIELD_T*)ptr;
		if (!peconv::validate_ptr(vBuf, vBufSize, to_check, sizeof(FIELD_T))) break;
		FIELD_T possible_rva = (*to_check);
		if (possible_rva == 0) continue;
		//std::cout << "checking: " << std::hex << possible_rva << std::endl;
		const peconv::ExportedFunc *exp = exportsMap->find_export_by_va(possible_rva);
		if (!exp) continue;

		IATBlock *iat_block = new IATBlock(vBuf, vBufSize, ptr);
		//validate IAT:
		size_t _iat_size = fill_iat<FIELD_T>(vBuf, vBufSize, exportsMap, *iat_block);
		if (_iat_size > 0) {
			iat_block->iat_size = _iat_size;
			return iat_block;
		}
		delete iat_block; iat_block = nullptr;
	}
	return nullptr;
}

