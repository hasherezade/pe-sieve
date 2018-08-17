#include "pe_reconstructor.h"

#include "../utils/workingset_enum.h"

#include "peconv.h"

//---

bool PeReconstructor::reconstruct(HANDLE processHandle)
{
	freeBuffer();

	ULONGLONG pe_va = artefacts.regionStart + artefacts.peBaseOffset;
	size_t pe_vsize = artefacts.calculatedImgSize;

	this->vBuf = peconv::alloc_aligned(pe_vsize, PAGE_READWRITE);
	if (!vBuf) {
		return false;
	}
	this->vBufSize = pe_vsize;

	bool is_ok = false;

	size_t read_size = peconv::read_remote_memory(processHandle, (BYTE*)pe_va, vBuf, pe_vsize);
	if (read_size == 0) {
		freeBuffer();
		return false;
	}

	if (!reconstructSectionsHdr(processHandle)) {
		return false;
	}

	bool is_pe_hdr = false;
	if (this->artefacts.hasNtHdrs()) {
		is_pe_hdr = reconstructPeHdr();
	}
	if (is_pe_hdr) {
		return true;
	}
	return false;
}

bool PeReconstructor::reconstructSectionsHdr(HANDLE processHandle)
{
	if (!this->vBuf) {
		return false;
	}

	if (!this->artefacts.hasSectionHdrs()) {
		return false;
	}

	ULONGLONG sec_offset = this->artefacts.secHdrsOffset - this->artefacts.peBaseOffset;
	BYTE *hdr_ptr = (sec_offset + vBuf);

	DWORD sec_rva = 0;
	size_t max_sec_size = 0;

	IMAGE_SECTION_HEADER* prev_sec = nullptr;
	IMAGE_SECTION_HEADER* curr_sec = (IMAGE_SECTION_HEADER*)(hdr_ptr);

	const ULONGLONG pe_img_base = (ULONGLONG)artefacts.peImageBase();

	for (size_t i = 0; i < artefacts.secCount; i++, curr_sec++) {
		if (!is_valid_section(vBuf, vBufSize, (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		sec_rva = curr_sec->VirtualAddress;
		DWORD sec_size = curr_sec->Misc.VirtualSize;

		ULONGLONG sec_va = pe_img_base + sec_rva;
		size_t real_sec_size = fetch_region_size(processHandle, (PBYTE)sec_va);
		if (sec_size > real_sec_size) {
			curr_sec->Misc.VirtualSize = DWORD(real_sec_size);
#ifdef _DEBUG
			std::cout << i << "# Fixed section size: " << std::hex
				<< sec_size << " vs real: " << real_sec_size << std::endl;
#endif
		}

		max_sec_size = (real_sec_size > max_sec_size) ? real_sec_size : max_sec_size;

		if (prev_sec && curr_sec->Misc.VirtualSize > 0) {
			ULONGLONG prev_sec_end = prev_sec->VirtualAddress + prev_sec->Misc.VirtualSize;
			if (prev_sec_end > curr_sec->VirtualAddress) {
				if (curr_sec->VirtualAddress > prev_sec->VirtualAddress) {
					DWORD diff = curr_sec->VirtualAddress - prev_sec->VirtualAddress;
					prev_sec->Misc.VirtualSize = diff;
#ifdef _DEBUG
					std::cout << "Trimmed section" << std::endl;
#endif
				}
			}
		}
		if (curr_sec->Misc.VirtualSize > 0) {
			prev_sec = curr_sec;
		}
	}

	if (max_sec_size == 0) {
		return false;
	}
	return true;
}

bool PeReconstructor::reconstructPeHdr()
{
	if (!this->vBuf) {
		return false;
	}

	if (!this->artefacts.hasNtHdrs()) {
		return false;
	}
	ULONGLONG nt_offset = this->artefacts.ntFileHdrsOffset - this->artefacts.peBaseOffset;
	BYTE* nt_ptr = (BYTE*)((ULONGLONG)this->vBuf + nt_offset);
	BYTE *pe_ptr = nt_ptr - sizeof(DWORD);

	if (!peconv::validate_ptr(vBuf, vBufSize, pe_ptr, sizeof(DWORD))) {
		return false;
	}
	IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32*)pe_ptr;
	//write signature:
	nt32->Signature = IMAGE_NT_SIGNATURE;

	LONG pe_offset = LONG((ULONGLONG)pe_ptr - (ULONGLONG)this->vBuf);
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*) vBuf;
	dosHdr->e_magic = IMAGE_DOS_SIGNATURE;
	dosHdr->e_lfanew = pe_offset;

	if (peconv::get_nt_hrds(vBuf)) {
		return true;
	}
	return false;
}

bool PeReconstructor::dumpToFile(std::string dumpFileName, IN OPTIONAL peconv::ExportsMapper* exportsMap)
{
	if (vBuf == nullptr) return false;

	// if the exportsMap is supplied, attempt to recover the (destroyed) import table:
	if (exportsMap != nullptr) {
		if (!peconv::fix_imports(vBuf, vBufSize, *exportsMap)) {
			std::cerr << "Unable to fix imports!" << std::endl;
		}
	}

	BYTE* dump_data = vBuf;
	size_t dump_size = vBufSize;
	size_t out_size = 0;
	BYTE* unmapped_module = nullptr;

	ULONGLONG start_addr = artefacts.regionStart + artefacts.peBaseOffset;
	if (unmap) {
		//if the image base in headers is invalid, set the current base and prevent from relocating PE:
		if (peconv::get_image_base(vBuf) == 0) {
			peconv::update_image_base(vBuf, (ULONGLONG)start_addr);
		}
		// unmap the PE file (convert from the Virtual Format into Raw Format)
		unmapped_module = peconv::pe_virtual_to_raw(vBuf, vBufSize, (ULONGLONG)start_addr, out_size, false);
		if (unmapped_module != NULL) {
			dump_data = unmapped_module;
			dump_size = out_size;
		}
	}
	// save the read module into a file
	bool is_dumped = peconv::dump_to_file(dumpFileName.c_str(), dump_data, dump_size);

	if (unmapped_module) {
		peconv::free_pe_buffer(unmapped_module, vBufSize);
	}
	return is_dumped;
}

