#include "iat_finder.h"

pesieve::IATBlock* pesieve::find_iat_block(
	IN bool is64bit,
	IN BYTE* vBuf,
	IN size_t vBufSize,
	IN const peconv::ExportsMapper* exportsMap,
	IN OPTIONAL size_t search_offset
)
{
	IATBlock* iat_block = nullptr;
	if (is64bit) {
		iat_block = find_iat<ULONGLONG>(true, vBuf, vBufSize, exportsMap, search_offset);
	}
	else {
		iat_block = find_iat<DWORD>(false, vBuf, vBufSize, exportsMap, search_offset);
	}
	return iat_block;
}

