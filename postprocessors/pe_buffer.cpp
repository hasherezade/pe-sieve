#include "pe_buffer.h"

#include <iostream>
#include "../scanners/artefact_scanner.h"
#include "../utils/artefacts_util.h"

size_t pesieve::PeBuffer::calcRemoteImgSize(ULONGLONG modBaseAddr) const
{
	const size_t hdr_buffer_size = PAGE_SIZE;
	BYTE hdr_buffer[hdr_buffer_size] = { 0 };
	size_t pe_vsize = 0;

	PIMAGE_SECTION_HEADER hdr_ptr = NULL;
	if (peconv::read_remote_pe_header(this->processHndl, (BYTE*)modBaseAddr, hdr_buffer, hdr_buffer_size)) {
		hdr_ptr = peconv::get_section_hdr(hdr_buffer, hdr_buffer_size, 0);
	}
	if (!hdr_ptr) {
		pe_vsize = peconv::fetch_region_size(this->processHndl, (PBYTE)modBaseAddr);
		//std::cout << "[!] Image size at: " << std::hex << modBaseAddr << " undetermined, using region size instead: " << pe_vsize << std::endl;
		return pe_vsize;
	}
	pe_vsize = ArtefactScanner::calcImgSize(this->processHndl, (HMODULE)modBaseAddr, hdr_buffer, hdr_buffer_size, hdr_ptr);
	//std::cout << "[!] Image size at: " << std::hex << modBaseAddr << " undetermined, using calculated img size: " << pe_vsize << std::endl;
	return pe_vsize;
}

bool pesieve::PeBuffer::readRemote(ULONGLONG module_base, size_t pe_vsize)
{
	if (pe_vsize == 0) {
		// if not size supplied, try with the size fetched from the header
		pe_vsize = peconv::get_remote_image_size(processHndl, (BYTE*)module_base);
	}
	if (_readRemote(module_base, pe_vsize)) {
		return true; //success
	}
	// try with the calculated size
	pe_vsize = calcRemoteImgSize(module_base);
#ifdef _DEBUG
	std::cout << "[!] Image size at: " << std::hex << module_base << " undetermined, using calculated size: " << pe_vsize << std::endl;
#endif
	return _readRemote(module_base, pe_vsize);
}

bool pesieve::PeBuffer::fillFromBuffer(ULONGLONG module_base, util::ByteBuffer& data_cache)
{
	size_t cached_size = data_cache.getDataSize();
	if (!cached_size) {
		return false;
	}
	if (!allocBuffer(cached_size)) {
		return false;
	}
	this->moduleBase = module_base;
	this->relocBase = module_base; //by default set the same as module base

	::memcpy(this->vBuf, data_cache.getData(), cached_size);
	return true;
}

bool  pesieve::PeBuffer::_readRemote(const ULONGLONG module_base, size_t pe_vsize)
{
	if (pe_vsize == 0) {
		return false;
	}
	if (!allocBuffer(pe_vsize)) {
		return false;
	}

	// store the base no matter if reading succeeded or failed
	this->moduleBase = module_base;
	this->relocBase = module_base; //by default set the same as module base

	const bool can_force_access = this->isRefl ? true : false;
	size_t read_size = peconv::read_remote_area(processHndl, (BYTE*)this->moduleBase, vBuf, pe_vsize, can_force_access);
	if (read_size != pe_vsize) {
#ifdef _DEBUG
		std::cout << "[!] Failed reading Image at: " << std::hex << this->moduleBase << " img size: " << pe_vsize << std::endl;
#endif
		freeBuffer();
		return false;
	}
	return true;
}

bool pesieve::PeBuffer::resizeBuffer(size_t new_size)
{
	if (!vBuf) return false;

	BYTE *new_buf = peconv::alloc_aligned(new_size, PAGE_READWRITE);
	if (!new_buf) {
		return false;
	}

	size_t smaller_size = (vBufSize < new_size) ? vBufSize : new_size;
	memcpy(new_buf, this->vBuf, smaller_size);
	freeBuffer();

	this->vBuf = new_buf;
	this->vBufSize = new_size;
	return true;
}

bool  pesieve::PeBuffer::resizeLastSection(size_t new_img_size)
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

	if (!peconv::update_image_size(vBuf, MASK_TO_DWORD(new_img_size))) {
		return false;
	}

	last_sec->Misc.VirtualSize = MASK_TO_DWORD(new_sec_vsize);
	last_sec->SizeOfRawData = MASK_TO_DWORD(new_sec_rsize);
	return true;
}

bool pesieve::PeBuffer::dumpPeToFile(
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
		const bool fixed = peconv::fix_imports(this->vBuf, this->vBufSize, *exportsMap, notCovered);
#ifdef _DEBUG
		if (!fixed) {
			std::cerr << "[-] Unable to fix imports!" << std::endl;
		}
#endif
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
	// dump PE in a given dump mode:
	return peconv::dump_pe(dumpFileName.c_str(), this->vBuf, this->vBufSize, this->relocBase, dumpMode);
}

bool pesieve::PeBuffer::dumpToFile(IN std::string dumpFileName)
{
	if (!vBuf) return false;
	return peconv::dump_to_file(dumpFileName.c_str(), vBuf, vBufSize);
}

bool pesieve::PeBuffer::isCode()
{
	if (!vBuf) return false;
	return pesieve::util::is_code(vBuf, vBufSize);
}
