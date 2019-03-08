#include "..\postprocessors\iat_finder.h"

IMAGE_IMPORT_DESCRIPTOR* find_import_table(BYTE* vBuf, size_t vBufSize, DWORD iat_offset, size_t search_offset)
{
	if (!vBuf || !iat_offset) return nullptr;
	if (search_offset > vBufSize || (vBufSize - search_offset) < sizeof(DWORD)) {
		return nullptr; //size check failed
	}
	size_t max_check = vBufSize - sizeof(DWORD);
	for (BYTE* ptr = vBuf + search_offset; ptr < vBuf + max_check; ptr++) {
		DWORD *to_check = (DWORD*)ptr;
		if (*to_check == iat_offset) { //candidate found
			size_t offset = (BYTE*)to_check - vBuf;
			std::cout << "Found IAT offset in the binary: " << std::hex << offset << "\n";
			size_t desc_diff = sizeof(IMAGE_IMPORT_DESCRIPTOR) - sizeof(DWORD);
			IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)to_check - desc_diff);
			if (!peconv::validate_ptr(vBuf, vBufSize, desc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
				continue; // candidate doesn't fit
			}
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
			}
			return desc;
		}
	}
	std::cout << "Import table not found\n";
	return nullptr;
}
