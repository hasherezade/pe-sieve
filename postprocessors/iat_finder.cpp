#include "..\postprocessors\iat_finder.h"

size_t calc_import_table_size(BYTE* vBuf, size_t vBufSize, IN peconv::ExportsMapper* exportsMap, IMAGE_IMPORT_DESCRIPTOR* first_desc)
{
	if (!vBuf || !exportsMap || !first_desc) return 0;

	IMAGE_IMPORT_DESCRIPTOR *desc = nullptr;
	for (desc = first_desc; ; desc++) {
		if (!peconv::validate_ptr(vBuf, vBufSize, desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			break; //buffer finished
		}
		if (desc->TimeDateStamp != 0 && desc->TimeDateStamp != (-1)) {
			return 0; // candidate doesn't fit
		}
		char* name_ptr = (char*)vBuf + desc->Name;
		if (!peconv::validate_ptr(vBuf, vBufSize, name_ptr, sizeof(char))) {
			return 0; // candidate doesn't fit
		}
		if (desc->Name) {
			if (!peconv::is_valid_import_name(vBuf, vBufSize, name_ptr)) return 0; //invalid name, validation failed
			std::cout << "DLL: " << name_ptr << "\n";
		}
		DWORD* orig_thunk_ptr = (DWORD*)(vBuf + desc->OriginalFirstThunk);
		if (!peconv::validate_ptr(vBuf, vBufSize, orig_thunk_ptr, sizeof(DWORD))) {
			return 0; // candidate doesn't fit
		}
		if (desc->FirstThunk == 0 && desc->OriginalFirstThunk == 0) {
			//probably the last chunk
			break;
		}
		DWORD *thunk_ptr = (DWORD*) (vBuf + desc->FirstThunk);
		const peconv::ExportedFunc *exp = exportsMap->find_export_by_va(*thunk_ptr);
		if (!exp) {
			return 0; //no such import: validation failed
		}
	}
	size_t diff = (BYTE*)desc - (BYTE*)first_desc;
	return diff + sizeof(IMAGE_IMPORT_DESCRIPTOR);
}

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
		std::cout << "Found IAT offset in the binary: " << std::hex << offset << "\n";
		size_t desc_diff = sizeof(IMAGE_IMPORT_DESCRIPTOR) - sizeof(DWORD);
		IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)to_check - desc_diff);
		if (!peconv::validate_ptr(vBuf, vBufSize, desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
			continue; // candidate doesn't fit
		}
		size_t _table_size = calc_import_table_size(vBuf, vBufSize, exportsMap, desc);
		if (_table_size > 0) {
			table_size = _table_size;
			return desc;
		}
		/*
		size_t desc_offset = (BYTE*)desc - vBuf;
		std::cout << "Desc offset: " << std::hex << desc_offset << std::endl;
		if (desc->Name == 0) continue;
		char* name_ptr = (char*)vBuf + desc->Name;
		if (!peconv::validate_ptr(vBuf, vBufSize, name_ptr, sizeof(char))) {
			continue; // candidate doesn't fit
		}
		if (!isalnum(name_ptr[0])) continue; // candidate doesn't fit
		if (strlen(name_ptr) == 0) continue;

		if (desc->TimeDateStamp != 0 || desc->OriginalFirstThunk == 0) continue;
		DWORD* orig_thunk = (DWORD*)(vBuf + desc->OriginalFirstThunk);
		if (!peconv::validate_ptr(vBuf, vBufSize, orig_thunk, sizeof(DWORD))) {
			continue; // candidate doesn't fit
		}*/
	}
	std::cout << "Import table not found\n";
	return nullptr;
}
