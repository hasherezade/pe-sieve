#include "pe_reconstructor.h"

#include "../utils/workingset_enum.h"

#include "iat_finder.h"
#include "import_table_finder.h"
#include <fstream>

//---
inline bool shift_artefacts(PeArtefacts& artefacts, size_t shift_size)
{
	artefacts.ntFileHdrsOffset += shift_size;
	artefacts.secHdrsOffset += shift_size;
	return true;
}

//WARNING: this function shifts also offsets saved in the artefacts
size_t PeReconstructor::shiftPeHeader()
{
	if (!this->artefacts.hasNtHdrs()) return 0;

	const size_t dos_pe_size = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_SIGNATURE);
	size_t diff = this->artefacts.ntFileHdrsOffset - this->artefacts.peBaseOffset;
	if (diff >= dos_pe_size) {
		return 0;
	}
	//TODO: shift the header
	if (!this->artefacts.hasSectionHdrs()) return 0; //cannot proceed

	size_t shift_size = dos_pe_size - diff;
	size_t hdrs_end = this->artefacts.secHdrsOffset + (this->artefacts.secCount + 1)* sizeof(IMAGE_SECTION_HEADER);
	if (!peconv::is_padding(vBuf + hdrs_end, shift_size, 0)) {
		return 0; // no empty space, cannot proceed
	}
	size_t hdrs_size = hdrs_end - this->artefacts.peBaseOffset;
	BYTE *new_nt_ptr = vBuf + this->artefacts.peBaseOffset + shift_size;
	if (!peconv::validate_ptr(vBuf, vBufSize, new_nt_ptr, hdrs_size)) {
		return 0;
	}

	size_t pe_offset = (this->artefacts.ntFileHdrsOffset - sizeof(IMAGE_NT_SIGNATURE)) - this->artefacts.peBaseOffset;

	IMAGE_DOS_HEADER dos_template = { 0 };
	dos_template.e_magic = IMAGE_DOS_SIGNATURE;
	dos_template.e_lfanew = pe_offset + shift_size;

	//check mz signature:
	BYTE *mz_ptr = vBuf + this->artefacts.peBaseOffset;
	if (!peconv::validate_ptr(vBuf, vBufSize, mz_ptr, sizeof(IMAGE_DOS_HEADER))) {
		return 0;
	}
	//check PE signature:
	DWORD* pe_ptr = (DWORD*)(vBuf + this->artefacts.peBaseOffset + dos_template.e_lfanew);
	if (!peconv::validate_ptr(vBuf, vBufSize, pe_ptr, sizeof(DWORD))) {
		return false;
	}
	//all checks passed, do the actual headers shift:
	memmove(new_nt_ptr, (vBuf + this->artefacts.peBaseOffset), hdrs_size);

	//write the DOS header:
	memcpy(mz_ptr, &dos_template, sizeof(IMAGE_DOS_HEADER));

	//write the PE signature:
	*pe_ptr = IMAGE_NT_SIGNATURE;

	shift_artefacts(this->artefacts, shift_size);
	return shift_size;
}

bool PeReconstructor::reconstruct(IN HANDLE processHandle)
{
	this->artefacts = origArtefacts;
	freeBuffer();

	this->moduleBase = artefacts.regionStart + artefacts.peBaseOffset;
	size_t pe_vsize = artefacts.calculatedImgSize;
	if (pe_vsize == 0) {
		pe_vsize = peconv::fetch_region_size(processHandle, (PBYTE)this->moduleBase);
		std::cout << "[!] Image size at: " << std::hex << moduleBase << " undetermined, using region size instead: " << pe_vsize << std::endl;
	}
	this->vBuf = peconv::alloc_aligned(pe_vsize, PAGE_READWRITE);
	if (!vBuf) {
		return false;
	}
	this->vBufSize = pe_vsize;

	size_t read_size = peconv::read_remote_area(processHandle, (BYTE*)moduleBase, vBuf, pe_vsize);
	if (read_size == 0) {
		freeBuffer();
		return false;
	}

	size_t shift_size = shiftPeHeader();
	if (shift_size) {
		std::cout << "[!] The PE header was shifted by: " << std::hex << shift_size << std::endl;
	}
	bool is_pe_hdr = false;
	if (this->artefacts.hasNtHdrs() && reconstructFileHdr()) {
		is_pe_hdr = reconstructPeHdr();
	}
	if (!is_pe_hdr) {
		return false;
	}
	//do not modify section headers if the PE is in raw format, or no unmapping requested
	if (!peconv::is_pe_raw(vBuf, pe_vsize)) {
		if (!fixSectionsVirtualSize(processHandle) || !fixSectionsCharacteristics(processHandle)) {
			return false;
		}
	}
	return true;
}

bool PeReconstructor::rebuildImportTable(IN peconv::ExportsMapper* exportsMap, IN const t_pesieve_imprec_mode &imprec_mode)
{
	if (!exportsMap) {
		return false;
	}
	if (!collectIATs(exportsMap)) {
		return false;
	}
	bool imp_recovered = false;
	if (imprec_mode == PE_IMPREC_UNERASE || imprec_mode == PE_IMPREC_AUTO) {
		std::cout << "[*] Trying to find ImportTable for module: " << std::hex << (ULONGLONG)this->moduleBase << "\n";
		bool imp_recovered = findImportTable(exportsMap);
		if (imp_recovered) {
			std::cout << "[+] ImportTable found.\n";
			return imp_recovered;
		}
	}
	if (imprec_mode == PE_IMPREC_REBUILD || imprec_mode == PE_IMPREC_AUTO) {
		std::cout << "[*] Trying to reconstruct ImportTable for module: " << std::hex << (ULONGLONG)this->moduleBase << "\n";
		imp_recovered = false; //TODO
	}
	return imp_recovered;
}

bool PeReconstructor::fixSectionsVirtualSize(HANDLE processHandle)
{
	if (!this->vBuf || !this->artefacts.hasSectionHdrs()) {
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
		size_t real_sec_size = peconv::fetch_region_size(processHandle, (PBYTE)sec_va);
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

bool PeReconstructor::fixSectionsCharacteristics(HANDLE processHandle)
{
	if (!this->vBuf || !this->artefacts.hasSectionHdrs()) {
		return false;
	}

	ULONGLONG sec_offset = this->artefacts.secHdrsOffset - this->artefacts.peBaseOffset;
	const BYTE *hdr_ptr = (sec_offset + vBuf);
	IMAGE_SECTION_HEADER* curr_sec = (IMAGE_SECTION_HEADER*)(hdr_ptr);

	const DWORD sec_all_flags = IMAGE_SCN_TYPE_NO_PAD
		| IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA
		| IMAGE_SCN_LNK_NRELOC_OVFL | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_NOT_CACHED
		| IMAGE_SCN_MEM_NOT_PAGED | IMAGE_SCN_MEM_SHARED | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
		| IMAGE_SCN_MEM_WRITE
		| IMAGE_SCN_NO_DEFER_SPEC_EXC | IMAGE_SCN_GPREL;

	for (size_t i = 0; i < artefacts.secCount; i++, curr_sec++) {
		if (!is_valid_section(vBuf, vBufSize, (BYTE*)curr_sec, 0)) {
			break;
		}
		//leave only the flags that are valid
		const DWORD charact = curr_sec->Characteristics;
		curr_sec->Characteristics = charact & sec_all_flags;
#ifdef DEBUG
		if (charact != curr_sec->Characteristics) {
			std::cout << "Section characteristics overwriten\n";
		}
#endif
	}
	return true;
}

bool PeReconstructor::reconstructFileHdr()
{
	if (!this->vBuf || !this->artefacts.hasNtHdrs()) {
		return false;
	}
	BYTE* loadedData = this->vBuf;
	size_t loadedSize = this->vBufSize;

	size_t nt_offset = this->artefacts.ntFileHdrsOffset - this->artefacts.peBaseOffset;
	BYTE* nt_ptr = (BYTE*)((ULONGLONG)this->vBuf + nt_offset);
	if (is_valid_file_hdr(this->vBuf, this->vBufSize, nt_ptr, 0)) {
		return true;
	}
	IMAGE_FILE_HEADER* hdr_candidate = (IMAGE_FILE_HEADER*)nt_ptr;
	if (!peconv::validate_ptr(loadedData, loadedSize, hdr_candidate, sizeof(IMAGE_FILE_HEADER))) {
		// probably buffer finished
		return false;
	}

	size_t opt_hdr_size = 0;
	if (artefacts.is64bit) {
		hdr_candidate->Machine = IMAGE_FILE_MACHINE_AMD64;
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER64);
	}
	else {
		hdr_candidate->Machine = IMAGE_FILE_MACHINE_I386;
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER32);
	}
	if (this->artefacts.secHdrsOffset) {
		size_t calc_offset = this->artefacts.secHdrsOffset - (nt_offset + sizeof(IMAGE_FILE_HEADER));
		if (calc_offset != opt_hdr_size) {
			std::cout << "[WARNING] Calculated sections header offset is different than the saved one!\n";
		}
		hdr_candidate->NumberOfSections = WORD(this->artefacts.secCount);
		hdr_candidate->SizeOfOptionalHeader = WORD(calc_offset);
	}

	hdr_candidate->NumberOfSymbols = 0;
	hdr_candidate->PointerToSymbolTable = 0;
	return true;
}

bool PeReconstructor::reconstructPeHdr()
{
	if (!this->vBuf || !this->artefacts.hasNtHdrs()) {
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

	bool is_fixed = false;
	if (is64bit) {
		is_fixed = overwrite_opt_hdr<IMAGE_OPTIONAL_HEADER64>(this->vBuf, this->vBufSize, (IMAGE_OPTIONAL_HEADER64*)&nt32->OptionalHeader, this->artefacts);
	}
	else {
		is_fixed = overwrite_opt_hdr<IMAGE_OPTIONAL_HEADER32>(this->vBuf, this->vBufSize, &nt32->OptionalHeader, this->artefacts);
	}
	if (!is_fixed) {
		return false;
	}
	if (!peconv::get_nt_hrds(vBuf)) {
		return false;
	}
	return true;
}

void PeReconstructor::printFoundIATs(std::string reportPath)
{
	if (!foundIATs.size()) {
		return;
	}
	std::ofstream report;
	report.open(reportPath);
	if (report.is_open() == false) {
		return;
	}

	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		report << itr->second->toString();
	}
	report.close();
}

bool PeReconstructor::dumpToFile(std::string dumpFileName, peconv::t_pe_dump_mode &dumpMode, IN OPTIONAL peconv::ExportsMapper* exportsMap)
{
	if (vBuf == nullptr) return false;

	bool is_dumped = false;
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
			is_dumped = peconv::dump_pe(dumpFileName.c_str(), vBuf, vBufSize, moduleBase, dumpMode, exportsMap);
			if (is_dumped) {
				return is_dumped;
			}
			is_dumped = peconv::PE_DUMP_AUTO; //revert and try again
		}
	}
	// save the read module into a file
	return peconv::dump_pe(dumpFileName.c_str(), vBuf, vBufSize, moduleBase, dumpMode, exportsMap);
}

IATBlock* PeReconstructor::findIAT(IN peconv::ExportsMapper* exportsMap, size_t start_offset)
{
	bool is64bit = peconv::is64bit(vBuf);
	
	IATBlock* iat_block = find_iat_block(is64bit, vBuf, vBufSize, exportsMap, start_offset);;
	if (!iat_block) {
		return nullptr;
	}
	size_t iat_size = iat_block->iat_size;
	DWORD iat_offset = iat_block->iat_ptr - vBuf;
	IMAGE_DATA_DIRECTORY *dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (dir) {
		if (iat_offset == dir->VirtualAddress && iat_size == dir->Size) {
			iat_block->isMain = true;
		}
	}
	return iat_block;
}

size_t PeReconstructor::collectIATs(IN peconv::ExportsMapper* exportsMap)
{
	size_t found = 0;
	for (size_t search_offset = 0; search_offset < vBufSize;) {

		IATBlock *currIAT = findIAT(exportsMap, search_offset);
		if (!currIAT) {
			//can't find any more IAT
			break;
		}
		found++;
		const DWORD iat_offset = currIAT->iat_ptr - vBuf;
		const size_t iat_end = iat_offset + currIAT->iat_size;
		if (!appendFoundIAT(iat_offset, currIAT)) {
			delete currIAT; //this IAT already exist in the map
		}
		// next search should be after thie current IAT:
		if (iat_end <= search_offset) {
			break; //this should never happen
		}
		search_offset = iat_end;
	}
	return found;
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
	IMAGE_IMPORT_DESCRIPTOR* import_table = nullptr;
	size_t table_size = 0;

	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock *currIAT = itr->second;

		const DWORD iat_offset = currIAT->iat_ptr - vBuf;
		const size_t iat_end = iat_offset + currIAT->iat_size;

		std::cout << "[*] Searching import table for IAT: " << std::hex << iat_offset << ", size: " << iat_dir->Size << std::endl;
		
		bool is64bit = peconv::is64bit(vBuf);
		import_table = find_import_table(
			is64bit,
			vBuf,
			vBufSize,
			exportsMap,
			iat_offset,
			table_size,
			0 //start offset
		);
		if (import_table) {
			//import table found, set it in the IATBlock:
			currIAT->importTable = import_table;
			//overwrite the Data Directory:
			iat_dir->VirtualAddress = iat_offset;
			iat_dir->Size = currIAT->iat_size;
			break; 
		}
	}

	if (!import_table) return false;
	
	DWORD imp_offset = (BYTE*)import_table - vBuf;
	if (imp_dir->VirtualAddress == imp_offset && imp_dir->Size == table_size) {
		//std::cout << "[*] Validated Imports offset!\n";
		return true;
	}
#ifdef _DEBUG
	if (imp_dir->Size == table_size) {
		std::cout << "[*] Validated Imports size!\n";
	}
#endif
	//overwrite the Data Directory:
	imp_dir->VirtualAddress = imp_offset;
	imp_dir->Size = table_size;
	return true;
}
