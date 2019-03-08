#include "pe_reconstructor.h"

#include "../utils/workingset_enum.h"

#include "iat_finder.h"

//---

bool PeReconstructor::reconstruct(IN HANDLE processHandle, IN OPTIONAL peconv::ExportsMapper* exportsMap)
{
	freeBuffer();

	this->moduleBase = artefacts.regionStart + artefacts.peBaseOffset;
	size_t pe_vsize = artefacts.calculatedImgSize;
	if (pe_vsize == 0) {
		pe_vsize = fetch_region_size(processHandle, (PBYTE)this->moduleBase);
		std::cout << "[!] Image size at: " << std::hex << moduleBase << " undetermined, using region size instead: " << pe_vsize << std::endl;
	}
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
	if (!is_pe_hdr) {
		return false;
	}
	std::cout << "Trying to find ImportTable\n";
	bool imp_found = findImportTable(exportsMap);
	std::cout << "---\n";
	return true;
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

	if (!peconv::get_nt_hrds(vBuf)) {
		return false;
	}
	return true;
}

bool PeReconstructor::dumpToFile(std::string dumpFileName, _In_opt_ peconv::ExportsMapper* exportsMap)
{
	if (vBuf == nullptr) return false;
	// save the read module into a file
	return peconv::dump_pe(dumpFileName.c_str(), vBuf, vBufSize, moduleBase, dumpMode, exportsMap);
}

bool PeReconstructor::findIAT(IN peconv::ExportsMapper* exportsMap)
{
	IMAGE_DATA_DIRECTORY *dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (!dir) {
		return false;
	}
	BYTE* iat_ptr = nullptr;
	bool is64bit = peconv::is64bit(vBuf);
	if (is64bit) {
		iat_ptr = find_iat<ULONGLONG>(vBuf, vBufSize, exportsMap, 0);
	}
	else {
		iat_ptr = find_iat<DWORD>(vBuf, vBufSize, exportsMap, 0);
	}
	
	if (!iat_ptr) return false;

	DWORD iat_offset = iat_ptr - vBuf;
	std::cout << "[+] Possible IAT found at: " << std::hex << iat_offset << std::endl;

	if (iat_offset == dir->VirtualAddress) {
		return true;
	}
	std::cout << "Overwriting IAT offset!\n";
	dir->VirtualAddress = iat_offset;
	return true;
}

bool PeReconstructor::findImportTable(IN peconv::ExportsMapper* exportsMap)
{
	IMAGE_DATA_DIRECTORY* imp_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IMPORT, true);
	if (!imp_dir) {
		return false;
	}
	IMAGE_DATA_DIRECTORY *iat_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (!iat_dir) {
		return false;
	}
	//if (iat_dir->VirtualAddress == 0) {
		if (!findIAT(exportsMap)) return false;
	//}
	DWORD iat_offset = iat_dir->VirtualAddress;

	std::cout << "Searching import table\n";
	IMAGE_IMPORT_DESCRIPTOR* import_table = find_import_table(vBuf, vBufSize, iat_offset, PAGE_SIZE);
	if (!import_table) return false;
	
	DWORD imp_offset = (BYTE*)import_table - vBuf;
	std::cout << "[+] Possible Import Table at offset: " << std::hex << imp_offset << std::endl;
	std::cout << "Overwriting Imports offset!\n";
	imp_dir->VirtualAddress = imp_offset;
	return true;
}
