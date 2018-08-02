#include "artefact_scanner.h"
/*
#include "../utils/path_converter.h"
*/
#include "../utils/workingset_enum.h"

#include "peconv.h"
#include "peconv/fix_imports.h"

#define PE_NOT_FOUND 0

bool is_valid_section(BYTE *loadedData, size_t loadedSize, BYTE *hdr_ptr, DWORD charact)
{
	PIMAGE_SECTION_HEADER hdr_candidate = (PIMAGE_SECTION_HEADER) hdr_ptr;
	if (!peconv::validate_ptr(loadedData, loadedSize, hdr_candidate, sizeof(IMAGE_SECTION_HEADER))) {
		// probably buffer finished
		return false;
	}
	if (hdr_candidate->PointerToRelocations != 0
		|| hdr_candidate->NumberOfRelocations != 0
		|| hdr_candidate->PointerToLinenumbers != 0)
	{
		//values that should be NULL are not
		return false;
	}
	if (charact != 0 && (hdr_candidate->Characteristics & charact) == 0) {
		// required characteristics not found
		//std::cout << "The section " << hdr_candidate->Name << " NOT  valid, charact:" << std::hex << hdr_candidate->Characteristics << std::endl;
		return false;
	}
	//std::cout << "The section " << hdr_candidate->Name << " is valid!" << std::endl;
	return true;
}

size_t count_section_hdrs(BYTE *loadedData, size_t loadedSize, IMAGE_SECTION_HEADER *hdr_ptr)
{
	size_t counter = 0;
	IMAGE_SECTION_HEADER* curr_sec = hdr_ptr;
	do {
		if (!is_valid_section(loadedData, loadedSize, (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		curr_sec++;
		counter++;
	} while (true);

	return counter;
}

//calculate image size basing on the sizes of sections
DWORD ArtefactScanner::calcImageSize(MemPageData &memPage, IMAGE_SECTION_HEADER *hdr_ptr)
{
	DWORD max_addr = 0;
	IMAGE_SECTION_HEADER* curr_sec = hdr_ptr;
	DWORD sec_rva = 0;
	size_t max_sec_size = 0;
	do {
		if (!is_valid_section(memPage.loadedData, memPage.loadedSize, (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		sec_rva = curr_sec->VirtualAddress;
		DWORD sec_size = curr_sec->Misc.VirtualSize;

		ULONGLONG sec_va = (ULONGLONG)memPage.region_start + sec_rva;
		size_t real_sec_size = fetch_region_size(processHandle, (PBYTE)sec_va);
		if (sec_size > real_sec_size) {
			std::cout << "[WARNING] Corrupt section size: " << std::hex
				<< sec_size << " vs real: " << real_sec_size << std::endl;
		}
		max_addr = (sec_rva > max_addr) ? sec_rva : max_addr;
		curr_sec++;

	} while (true);

	ULONGLONG last_sec_va = (ULONGLONG)memPage.region_start + max_addr;
	size_t last_sec_size = fetch_region_size(processHandle, (PBYTE)last_sec_va);
	size_t total_size = max_addr + last_sec_size;
	std::cout << "Total Size:" << std::hex << total_size << std::endl;
	return total_size;
}

IMAGE_SECTION_HEADER* get_first_section(BYTE *loadedData, size_t loadedSize, IMAGE_SECTION_HEADER *hdr_ptr)
{
	IMAGE_SECTION_HEADER* prev_sec = hdr_ptr;
	do {
		if (!is_valid_section(loadedData, loadedSize, (BYTE*) prev_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		hdr_ptr = prev_sec;
		prev_sec--;
	} while (true);

	return hdr_ptr;
}

IMAGE_SECTION_HEADER* ArtefactScanner::findSectionsHdr(MemPageData &memPage)
{
	if (memPage.loadedData == nullptr) {
		if (!memPage.loadRemote()) return nullptr;
		if (memPage.loadedData == nullptr) return nullptr;
	}
	//find sections table
	char sec_name[] = ".text";
	BYTE *hdr_ptr = find_pattern(memPage.loadedData, memPage.loadedSize, (BYTE*)sec_name, strlen(sec_name));
	if (!hdr_ptr) {
		return nullptr;
	}
	DWORD charact = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	if (!is_valid_section(memPage.loadedData, memPage.loadedSize, hdr_ptr, charact)) {
		return nullptr;
	}
	// is it really the first section?
	IMAGE_SECTION_HEADER *first_sec = get_first_section(memPage.loadedData, memPage.loadedSize, (IMAGE_SECTION_HEADER*) hdr_ptr);
	return (IMAGE_SECTION_HEADER*)first_sec;
}

bool is_valid_file_hdr(BYTE *loadedData, size_t loadedSize, BYTE *hdr_ptr, DWORD charact)
{
	IMAGE_FILE_HEADER* hdr_candidate = (IMAGE_FILE_HEADER*)hdr_ptr;
	if (!peconv::validate_ptr(loadedData, loadedSize, hdr_candidate, sizeof(IMAGE_FILE_HEADER))) {
		// probably buffer finished
		return false;
	}
	if (hdr_candidate->NumberOfSections > 100) {
		return false;
	}
	if (hdr_candidate->NumberOfSymbols != 0 || hdr_candidate->PointerToSymbolTable != 0) {
		return false;
	}
	if (charact != 0 && (hdr_candidate->Characteristics & charact) == 0) {
		return false;
	}
	return true;
}

BYTE* ArtefactScanner::findNtFileHdr(BYTE* loadedData, size_t loadedSize)
{
	if (loadedData == nullptr) {
		return nullptr;
	}
	typedef enum {
		ARCH_32B = 0, 
		ARCH_64B = 1, 
		ARCHS_COUNT
	} t_archs;

	WORD archs[ARCHS_COUNT] = { 0 };
	archs[ARCH_32B] = 0x014c;
	archs[ARCH_64B] = 0x8664;

	BYTE *arch_ptr = nullptr;
	size_t my_arch = 0;
	for (my_arch = ARCH_32B; my_arch < ARCHS_COUNT; my_arch++) {
		arch_ptr = find_pattern(loadedData, loadedSize, (BYTE*)&archs[my_arch], sizeof(WORD));
		if (arch_ptr) {
			break;
		}
	}
	if (!arch_ptr) {
		return nullptr;
	}
	DWORD charact = IMAGE_FILE_EXECUTABLE_IMAGE;
	if (my_arch == ARCH_32B) {
		charact |= IMAGE_FILE_32BIT_MACHINE;
	}
	else {
		charact |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
	}
	if (!is_valid_file_hdr(loadedData, loadedSize, arch_ptr, charact)) {
		return nullptr;
	}
	return arch_ptr;
}

PeArtefacts* ArtefactScanner::findArtefacts(MemPageData &memPage)
{
	IMAGE_SECTION_HEADER* sec_hdr = findSectionsHdr(memPage);
	if (!sec_hdr) {
		return nullptr;
	}
	PeArtefacts *peArt = new PeArtefacts();
	peArt->region_start = memPage.region_start;
	peArt->sec_count = count_section_hdrs(memPage.loadedData, memPage.loadedSize, sec_hdr);
	peArt->calculated_img_size = calcImageSize(memPage, sec_hdr);
	peArt->sec_hdr_offset = (ULONGLONG)sec_hdr - (ULONGLONG)memPage.loadedData;
	return peArt;
}

ArtefactScanReport* ArtefactScanner::scanRemote()
{
	if (this->prevMemPage) {
		delete this->prevMemPage;
		this->prevMemPage = nullptr;
	}

	bool is_damaged_pe = false;
	// it may still contain a damaged PE header...
	ULONGLONG region_start = memPage.region_start;
	MemPageData *artPagePtr = &memPage;

	PeArtefacts *peArt = findArtefacts(memPage);
	if (!peArt  && (region_start > memPage.alloc_base)) {
		this->prevMemPage = new MemPageData (this->processHandle, memPage.alloc_base);
		artPagePtr = prevMemPage;
		region_start = prevMemPage->region_start;
		peArt = findArtefacts(*prevMemPage);
	}
	if (!peArt) {
		//no artefacts found
		return nullptr;
	}

	BYTE* nt_file_hdr = findNtFileHdr(artPagePtr->loadedData, size_t(peArt->sec_hdr_offset));
	if (nt_file_hdr) {
		peArt->file_hdr_offset = (ULONGLONG)nt_file_hdr - (ULONGLONG)artPagePtr->loadedData;
	}

	const size_t region_size = size_t(memPage.region_end - region_start);
	ArtefactScanReport *my_report = new ArtefactScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS, *peArt);
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;

	if (peArt->calculated_img_size > region_size) {
		my_report->moduleSize = peArt->calculated_img_size;
	}
	delete peArt;
	return my_report;
}

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
			std::cout << i << "# Fixed section size: " << std::hex
				<< sec_size << " vs real: " << real_sec_size << std::endl;
		}

		max_sec_size = (real_sec_size > max_sec_size) ? real_sec_size : max_sec_size;

		if (prev_sec && curr_sec->Misc.VirtualSize > 0) {
			ULONGLONG prev_sec_end = prev_sec->VirtualAddress + prev_sec->Misc.VirtualSize;
			if (prev_sec_end > curr_sec->VirtualAddress) {
				if (curr_sec->VirtualAddress > prev_sec->VirtualAddress) {
					DWORD diff = curr_sec->VirtualAddress - prev_sec->VirtualAddress;
					prev_sec->Misc.VirtualSize = diff;
					std::cout << "Trimmed section" << std::endl;
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

