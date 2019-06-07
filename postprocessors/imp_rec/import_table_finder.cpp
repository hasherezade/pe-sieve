#include "import_table_finder.h"

IMAGE_IMPORT_DESCRIPTOR* find_import_table(
	IN bool is64bit,
	IN BYTE* vBuf,
	IN size_t vBufSize,
	IN peconv::ExportsMapper* exportsMap,
	IN DWORD iat_offset,
	OUT size_t &table_size,
	IN OPTIONAL size_t search_offset
)
{
	IMAGE_IMPORT_DESCRIPTOR* import_table = nullptr;
	if (is64bit) {
		import_table = find_import_table<ULONGLONG>(
			vBuf,
			vBufSize,
			exportsMap,
			iat_offset,
			table_size,
			0 //start offset
			);
	}
	else {
		import_table = find_import_table<DWORD>(
			vBuf,
			vBufSize,
			exportsMap,
			iat_offset,
			table_size,
			0 //start offset
			);
	}
	return import_table;
}
