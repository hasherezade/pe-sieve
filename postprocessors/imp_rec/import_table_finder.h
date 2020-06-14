#pragma once
#include <peconv.h>

namespace pesieve {

	template <typename FIELD_T>
	bool is_valid_import_descriptor(BYTE* vBuf, size_t vBufSize, IN const peconv::ExportsMapper* exportsMap, IMAGE_IMPORT_DESCRIPTOR* desc)
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
	size_t calc_import_table_size(BYTE* vBuf, size_t vBufSize, IN const peconv::ExportsMapper* exportsMap, IMAGE_IMPORT_DESCRIPTOR* first_desc)
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
	IMAGE_IMPORT_DESCRIPTOR* find_first_import_descriptor(BYTE* vBuf, size_t vBufSize, IN const peconv::ExportsMapper* exportsMap, IMAGE_IMPORT_DESCRIPTOR* found_desc)
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
	IMAGE_IMPORT_DESCRIPTOR* find_import_table_tpl(IN BYTE* vBuf,
		IN size_t vBufSize,
		IN const peconv::ExportsMapper* exportsMap,
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

	IMAGE_IMPORT_DESCRIPTOR* find_import_table(
		IN bool is64bit,
		IN BYTE* vBuf,
		IN size_t vBufSize,
		IN const peconv::ExportsMapper* exportsMap,
		IN DWORD iat_offset,
		OUT size_t &table_size,
		IN OPTIONAL size_t search_offset
	);

}; //namespace pesieve

