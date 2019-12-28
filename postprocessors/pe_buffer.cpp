#include "pe_buffer.h"

#include <iostream>

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

bool PeBuffer::dumpPeToFile(IN std::string dumpFileName, IN OUT peconv::t_pe_dump_mode &dumpMode, IN OPTIONAL const peconv::ExportsMapper* exportsMap)
{
	if (!vBuf || !isValidPe()) return false;

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
			bool is_dumped = peconv::dump_pe(dumpFileName.c_str(), vBuf, vBufSize, moduleBase, dumpMode, exportsMap);
			if (is_dumped) {
				return is_dumped;
			}
			dumpMode = peconv::PE_DUMP_AUTO; //revert and try again
		}
	}
	// save the read module into a file
	return peconv::dump_pe(dumpFileName.c_str(), vBuf, vBufSize, moduleBase, dumpMode, exportsMap);
}

bool PeBuffer::dumpToFile(IN std::string dumpFileName)
{
	if (!vBuf) return false;
	return peconv::dump_to_file(dumpFileName.c_str(), vBuf, vBufSize);
}
