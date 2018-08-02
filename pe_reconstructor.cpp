#include "pe_reconstructor.h"

#include "../utils/workingset_enum.h"

#include "peconv.h"
#include "peconv/fix_imports.h"
//---

bool PeReconstructor::reconstruct(HANDLE processHandle)
{
	if (!this->report) {
		return false;
	}
	freeBuffer();

	this->vBuf = peconv::alloc_aligned(report->moduleSize, PAGE_READWRITE);
	if (!vBuf) {
		return false;
	}
	this->vBufSize = report->moduleSize;

	bool is_ok = false;
	size_t read_size = peconv::read_remote_memory(processHandle, (BYTE*)report->module, vBuf, report->moduleSize);
	if (read_size == 0) {
		freeBuffer();
		return false;
	}

	if (!reconstructSectionsHdr(processHandle)) {
		return false;
	}

	bool is_pe_hdr = false;
	if (this->report->nt_file_hdr) {
		is_pe_hdr = reconstructPeHdr();
	}
	if (is_pe_hdr) {
		return true;
	}
	return false;
}

bool PeReconstructor::reconstructSectionsHdr(HANDLE processHandle)
{
	if (!this->report || !this->vBuf) {
		return false;
	}

	if (this->report->sections_hdrs < (ULONGLONG)this->report->module) {
		return false;
	}

	ULONGLONG sec_offset = (this->report->sections_hdrs - (ULONGLONG)this->report->module);
	BYTE *hdr_ptr = (sec_offset + vBuf);

	DWORD sec_rva = 0;
	size_t max_sec_size = 0;

	IMAGE_SECTION_HEADER* prev_sec = nullptr;
	IMAGE_SECTION_HEADER* curr_sec = (IMAGE_SECTION_HEADER*)(hdr_ptr);

	for (size_t i = 0; i < report->sections_count; i++, curr_sec++) {
		if (!is_valid_section(vBuf, vBufSize, (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		sec_rva = curr_sec->VirtualAddress;
		DWORD sec_size = curr_sec->Misc.VirtualSize;

		ULONGLONG sec_va = (ULONGLONG)report->module + sec_rva;
		size_t real_sec_size = fetch_region_size(processHandle, (PBYTE)sec_va);
		if (sec_size > real_sec_size) {
			curr_sec->Misc.VirtualSize = real_sec_size;
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
	if (!this->report || !this->vBuf) {
		return false;
	}

	if (this->report->nt_file_hdr < (ULONGLONG)this->report->module) {
		return false;
	}
	ULONGLONG nt_offset = this->report->nt_file_hdr - (ULONGLONG)this->report->module;
	BYTE* nt_ptr = (BYTE*)((ULONGLONG)this->vBuf + nt_offset);
	BYTE *pe_ptr = nt_ptr - sizeof(DWORD);

	if (!peconv::validate_ptr(vBuf, vBufSize, pe_ptr, sizeof(DWORD))) {
		return false;
	}
	IMAGE_NT_HEADERS32 *nt32 = (IMAGE_NT_HEADERS32*)pe_ptr;
	//write signature:
	nt32->Signature = IMAGE_NT_SIGNATURE;

	LONG pe_offset = (ULONGLONG)pe_ptr - (ULONGLONG)this->vBuf;
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

	ULONGLONG start_addr = (ULONGLONG) report->module;
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

