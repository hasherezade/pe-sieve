#include "pe_buffer.h"

#include <iostream>


class ImportInfoCallback : public peconv::ImportThunksCallback
{
public:
	ImportInfoCallback(BYTE* _modulePtr, size_t _moduleSize, std::map<ULONGLONG, peconv::ExportedFunc> &_storedFunc)
		: ImportThunksCallback(_modulePtr, _moduleSize), storedFunc(_storedFunc)
	{
	}

	virtual bool processThunks(LPSTR lib_name, ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr)
	{
		if (this->is64b) {
			IMAGE_THUNK_DATA64* desc = reinterpret_cast<IMAGE_THUNK_DATA64*>(origFirstThunkPtr);
			ULONGLONG* call_via = reinterpret_cast<ULONGLONG*>(firstThunkPtr);
			return processThunks_tpl<ULONGLONG, IMAGE_THUNK_DATA64>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG64);
		}
		IMAGE_THUNK_DATA32* desc = reinterpret_cast<IMAGE_THUNK_DATA32*>(origFirstThunkPtr);
		DWORD* call_via = reinterpret_cast<DWORD*>(firstThunkPtr);
		return processThunks_tpl<DWORD, IMAGE_THUNK_DATA32>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG32);
	}

protected:
	template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
	bool processThunks_tpl(LPSTR lib_name, T_IMAGE_THUNK_DATA* desc, T_FIELD* call_via, T_FIELD ordinal_flag)
	{
		ULONGLONG call_resolved = (*call_via);
		T_FIELD raw_ordinal = 0;
		bool is_by_ord = (desc->u1.Ordinal & ordinal_flag) != 0;
		if (is_by_ord) {
			raw_ordinal = desc->u1.Ordinal & (~ordinal_flag);
#ifdef _DEBUG
			std::cout << "raw ordinal: " << std::hex << raw_ordinal << std::endl;
#endif
			this->storedFunc[call_resolved] = peconv::ExportedFunc(peconv::get_dll_shortname(lib_name), raw_ordinal);
		}
		else {
			PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
			LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
			raw_ordinal = by_name->Hint;
			this->storedFunc[call_resolved] = peconv::ExportedFunc(peconv::get_dll_shortname(lib_name), func_name, raw_ordinal);
		}
		return true;
	}

	//fields:
	std::map<ULONGLONG, peconv::ExportedFunc> &storedFunc;
};
///----

bool PeBuffer::readRemote(HANDLE process_hndl, ULONGLONG module_base, size_t pe_vsize)
{
	if (pe_vsize == 0) {
		pe_vsize = peconv::fetch_region_size(process_hndl, (PBYTE)module_base);
		std::cout << "[!] Image size at: " << std::hex << module_base << " undetermined, using region size instead: " << pe_vsize << std::endl;
	}
	if (!allocBuffer(pe_vsize)) {
		return false;
	}
	size_t read_size = peconv::read_remote_area(process_hndl, (BYTE*)module_base, vBuf, pe_vsize);
	if (read_size == 0) {
		freeBuffer();
		return false;
	}
	this->moduleBase = module_base;
	this->relocBase = module_base; //by default set the same as module base
	return true;
}

bool PeBuffer::resizeBuffer(size_t new_size)
{
	if (!vBuf) return false;

	BYTE *new_buf = peconv::alloc_aligned(new_size, PAGE_READWRITE);
	if (!new_buf) {
		return false;
	}
	//preserve the module base:
	ULONGLONG module_base = this->moduleBase;

	size_t smaller_size = (vBufSize < new_size) ? vBufSize : new_size;
	memcpy(new_buf, this->vBuf, smaller_size);
	freeBuffer();

	this->moduleBase = module_base;
	this->vBuf = new_buf;
	this->vBufSize = new_size;
	return true;
}

bool PeBuffer::resizeLastSection(size_t new_img_size)
{
	if (!vBuf) return false;

	PIMAGE_SECTION_HEADER last_sec = peconv::get_last_section(vBuf, vBufSize, false);
	if (!last_sec) {
		return false;
	}

	if (new_img_size < last_sec->VirtualAddress) {
		return false;
	}

	const size_t new_sec_vsize = new_img_size - last_sec->VirtualAddress;
	const size_t new_sec_rsize = new_sec_vsize;

	if (last_sec->VirtualAddress + new_sec_vsize > this->vBufSize) {
		//buffer too small
		return false;
	}

	if (!peconv::update_image_size(vBuf, new_img_size)) {
		return false;
	}

	last_sec->Misc.VirtualSize = new_sec_vsize;
	last_sec->SizeOfRawData = new_sec_rsize;
	return true;
}

bool PeBuffer::dumpPeToFile(
	IN std::string dumpFileName,
	IN OUT peconv::t_pe_dump_mode &dumpMode,
	IN OPTIONAL const peconv::ExportsMapper* exportsMap,
	OUT OPTIONAL peconv::ImpsNotCovered *notCovered
)
{
	if (!vBuf || !isValidPe()) return false;
#ifdef _DEBUG
	std::cout << "Dumping using relocBase: " << std::hex << relocBase << "\n";
#endif
	if (exportsMap != nullptr) {
		if (!peconv::fix_imports(this->vBuf, this->vBufSize, *exportsMap, notCovered)) {
			std::cerr << "[-] Unable to fix imports!" << std::endl;
		}
	}
	if (dumpMode == peconv::PE_DUMP_AUTO) {
		bool is_raw_alignment_valid = peconv::is_valid_sectons_alignment(vBuf, vBufSize, true);
		bool is_virtual_alignment_valid = peconv::is_valid_sectons_alignment(vBuf, vBufSize, false);
#ifdef _DEBUG
		std::cout << "Is raw alignment valid: " << is_raw_alignment_valid << std::endl;
		std::cout << "Is virtual alignment valid: " << is_virtual_alignment_valid << std::endl;
#endif
		if (!is_raw_alignment_valid && is_virtual_alignment_valid) {
			//in case if raw alignment is invalid and virtual valid, try to dump using Virtual Alignment first
			dumpMode = peconv::PE_DUMP_REALIGN;
			bool is_dumped = peconv::dump_pe(dumpFileName.c_str(), this->vBuf, this->vBufSize, this->relocBase, dumpMode);
			if (is_dumped) {
				return is_dumped;
			}
			dumpMode = peconv::PE_DUMP_AUTO; //revert and try again
		}
	}
	// save the read module into a file
	return peconv::dump_pe(dumpFileName.c_str(), this->vBuf, this->vBufSize, this->relocBase, dumpMode);
}

bool PeBuffer::dumpToFile(IN std::string dumpFileName)
{
	if (!vBuf) return false;
	return peconv::dump_to_file(dumpFileName.c_str(), vBuf, vBufSize);
}


void PeBuffer::listAllImports(std::map<ULONGLONG, peconv::ExportedFunc> &_storedFunc)
{
	ImportInfoCallback callback(vBuf, vBufSize, _storedFunc);
	peconv::process_import_table(vBuf, vBufSize, &callback);
}
