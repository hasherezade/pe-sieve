#include "pe_reconstructor.h"

#include "../utils/workingset_enum.h"

#include "peconv.h"

//---

bool PeReconstructor::reconstruct(HANDLE processHandle)
{
	freeBuffer();

	this->moduleBase = artefacts.regionStart + artefacts.peBaseOffset;
	size_t pe_vsize = artefacts.calculatedImgSize;

	this->vBuf = peconv::alloc_aligned(pe_vsize, PAGE_READWRITE);
	if (!vBuf) {
		return false;
	}
	this->vBufSize = pe_vsize;

	bool is_ok = false;

	size_t read_size = peconv::read_remote_memory(processHandle, (BYTE*)moduleBase, vBuf, pe_vsize);
	if (read_size == 0) {
		freeBuffer();
		return false;
	}

	//do not modify section headers if the PE is in raw format, or no unmapping requested
	if (!peconv::is_pe_raw(vBuf, pe_vsize)) {
		if (!reconstructSectionsHdr(processHandle)) {
			return false;
		}
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

	IMAGE_FILE_HEADER *file_hdr = &nt32->FileHeader;

	bool is64bit = (file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64) ? true : false;

	if (nt32->FileHeader.SizeOfOptionalHeader == 0) {
		nt32->FileHeader.SizeOfOptionalHeader = is64bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
	}
	LONG pe_offset = LONG((ULONGLONG)pe_ptr - (ULONGLONG)this->vBuf);
	IMAGE_DOS_HEADER* dosHdr = (IMAGE_DOS_HEADER*) vBuf;
	dosHdr->e_magic = IMAGE_DOS_SIGNATURE;
	dosHdr->e_lfanew = pe_offset;

	if (peconv::get_nt_hrds(vBuf)) {
		return true;
	}
	return false;
}

bool PeReconstructor::dumpToFile(std::string dumpFileName, _In_opt_ peconv::ExportsMapper* exportsMap)
{
	if (vBuf == nullptr) return false;
	// save the read module into a file
	return peconv::dump_pe(dumpFileName.c_str(), vBuf, vBufSize, moduleBase, dumpMode, exportsMap);
}
