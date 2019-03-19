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
#ifdef _DEBUG
		std::cout << std::hex << offset << " : " << exp->funcName << std::endl;
#endif
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
	for (BYTE* ptr = vBuf + search_offset; ptr < vBuf + max_check; ptr++) {
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

template <typename FIELD_T>
bool is_valid_import_descriptor(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, IMAGE_IMPORT_DESCRIPTOR* desc)
{
	if (!peconv::validate_ptr(vBuf, vBufSize, desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
		return false; //buffer finished
	}
	if (desc->TimeDateStamp != 0 && desc->TimeDateStamp != (-1)) {
		return false; // candidate doesn't fit
	}
	char* name_ptr = (char*)vBuf + desc->Name;
	if (!peconv::validate_ptr(vBuf, vBufSize, name_ptr, sizeof(char))) {
		return false; // candidate doesn't fit
	}
	if (desc->Name) {
		if (!peconv::is_valid_import_name(vBuf, vBufSize, name_ptr)) return 0; //invalid name, validation failed
#ifdef _DEBUG
		std::cout << "DLL: " << name_ptr << "\n";
#endif
	}
	if (desc->FirstThunk == 0 && desc->OriginalFirstThunk == 0) {
		//probably the last chunk
		return true;
	}
	FIELD_T* orig_thunk_ptr = (FIELD_T*)(vBuf + desc->OriginalFirstThunk);
	if (!peconv::validate_ptr(vBuf, vBufSize, orig_thunk_ptr, sizeof(FIELD_T))) {
		return false; // candidate doesn't fit
	}
	FIELD_T *thunk_ptr = (FIELD_T*)(vBuf + desc->FirstThunk);
	if (!peconv::validate_ptr(vBuf, vBufSize, thunk_ptr, sizeof(FIELD_T))) {
		return false; // candidate doesn't fit
	}
	const peconv::ExportedFunc *exp = exportsMap->find_export_by_va(*thunk_ptr);
	if (!exp) {
		return false; //no such import: validation failed
	}
	return true;
}

template <typename FIELD_T>
IMAGE_IMPORT_DESCRIPTOR* find_first_import_descriptor(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, IMAGE_IMPORT_DESCRIPTOR* found_desc)
{
	if (!vBuf || !exportsMap || !found_desc) return nullptr;

	IMAGE_IMPORT_DESCRIPTOR *first_desc = nullptr;
	size_t prev_table_size = 0;

	for (IMAGE_IMPORT_DESCRIPTOR *desc = found_desc; ; desc--) {
		size_t table_size = calc_import_table_size<FIELD_T>(vBuf, vBufSize, exportsMap, desc);
		if (table_size == 0 || table_size < prev_table_size) {
			break; // if it is valid, the table size should grow
		}
		prev_table_size = table_size;
		first_desc = desc;
		//std::cout << "!!! Valid DESC: " << std::hex << (ULONGLONG)((BYTE*)desc - vBuf) << std::endl;
	}
	return first_desc;
}

template <typename FIELD_T>
size_t calc_import_table_size(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, IMAGE_IMPORT_DESCRIPTOR* first_desc)
{
	if (!vBuf || !exportsMap || !first_desc) return 0;

	IMAGE_IMPORT_DESCRIPTOR *desc = nullptr;
	for (desc = first_desc; ; desc++) {
		if (!peconv::validate_ptr(vBuf, vBufSize, desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			break; //buffer finished
		}
		if (!is_valid_import_descriptor<FIELD_T>(vBuf, vBufSize, exportsMap, desc)) {
			return 0;
		}
		if (desc->FirstThunk == 0 && desc->OriginalFirstThunk == 0) {
			//probably the last chunk
			break;
		}
	}
	size_t diff = (BYTE*)desc - (BYTE*)first_desc;
	return diff + sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

template <typename FIELD_T>
IMAGE_IMPORT_DESCRIPTOR* find_import_table(IN BYTE* vBuf,
	IN size_t vBufSize,
	IN peconv::ExportsMapper* exportsMap,
	IN DWORD iat_offset,
	OUT size_t &table_size,
	IN OPTIONAL size_t search_offset)
{
	table_size = 0;
	if (!vBuf || !iat_offset) return nullptr;
	if (search_offset > vBufSize || (vBufSize - search_offset) < sizeof(DWORD)) {
		return nullptr; //size check failed
	}
	size_t max_check = vBufSize - sizeof(DWORD);
	for (BYTE* ptr = vBuf + search_offset; ptr < vBuf + max_check; ptr++) {
		DWORD *to_check = (DWORD*)ptr;
		if (*to_check != iat_offset) {
			continue; //candidate not found
		}
		size_t offset = (BYTE*)to_check - vBuf;
		//std::cout << "Found IAT offset in the binary: " << std::hex << offset << "\n";
		size_t desc_diff = sizeof(IMAGE_IMPORT_DESCRIPTOR) - sizeof(DWORD);
		IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)to_check - desc_diff);
		if (!peconv::validate_ptr(vBuf, vBufSize, desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			continue; // candidate doesn't fit
		}
		//now try to find the first one in the table:
		IMAGE_IMPORT_DESCRIPTOR* first_desc = find_first_import_descriptor<FIELD_T>(vBuf, vBufSize, exportsMap, desc);
		size_t _table_size = calc_import_table_size<FIELD_T>(vBuf, vBufSize, exportsMap, first_desc);
		if (_table_size > 0) {
			table_size = _table_size;
			return first_desc;
		}
	}
	//std::cout << "Import table not found\n";
	return nullptr;
}
