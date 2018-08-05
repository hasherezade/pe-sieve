#include "artefact_scanner.h"

#include "../utils/workingset_enum.h"

#include "peconv.h"
#include "peconv/fix_imports.h"

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
	if (!loadedData || !hdr_ptr) {
		return 0;
	}
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

ULONGLONG ArtefactScanner::calcPeBase(MemPageData &memPage, BYTE *sec_hdr)
{
	ULONGLONG pe_base_offset = 0;

	ULONGLONG hdrs_offset = (ULONGLONG)sec_hdr - (ULONGLONG)memPage.getLoadedData();
	for (ULONGLONG offset = hdrs_offset; offset > PAGE_SIZE; offset -= PAGE_SIZE) {
		pe_base_offset += PAGE_SIZE;
	}
	pe_base_offset += memPage.region_start;
	return pe_base_offset;
}

//calculate image size basing on the sizes of sections
size_t ArtefactScanner::calcImageSize(MemPageData &memPage, IMAGE_SECTION_HEADER *hdr_ptr, ULONGLONG pe_image_base)
{
	if (!hdr_ptr) return 0;

	DWORD max_addr = 0;
	IMAGE_SECTION_HEADER* curr_sec = hdr_ptr;
	DWORD sec_rva = 0;
	size_t max_sec_size = 0;
	do {
		if (!is_valid_section(memPage.getLoadedData(), memPage.getLoadedSize(), (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		sec_rva = curr_sec->VirtualAddress;
		max_addr = (sec_rva > max_addr) ? sec_rva : max_addr;
		curr_sec++;

	} while (true);

	ULONGLONG last_sec_va = pe_image_base + max_addr;
	size_t last_sec_size = fetch_region_size(processHandle, (PBYTE)last_sec_va);
	size_t total_size = max_addr + last_sec_size;
#ifdef _DEBUG
	std::cout << "Total Size:" << std::hex << total_size << std::endl;
#endif
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

BYTE* ArtefactScanner::findSecByPatterns(MemPageData &memPage)
{
	if (!memPage.load()) {
		return nullptr;
	}
	//find sections table
	char sec_name[] = ".text";
	BYTE *hdr_ptr = find_pattern(memPage.getLoadedData(), memPage.getLoadedSize(), (BYTE*)sec_name, strlen(sec_name));
	if (hdr_ptr) {
		return hdr_ptr;
	}
	// try another pattern
	BYTE sec_ending[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x60
	};
	const size_t sec_ending_size = sizeof(sec_ending);
	hdr_ptr = find_pattern(memPage.getLoadedData(), memPage.getLoadedSize(), sec_ending, sec_ending_size);
	if (!hdr_ptr) {
		return nullptr;
	}
	size_t offset_to_bgn = sizeof(IMAGE_SECTION_HEADER) - sec_ending_size;
	hdr_ptr -= offset_to_bgn;
	if (!peconv::validate_ptr(memPage.getLoadedData(), memPage.getLoadedSize(), hdr_ptr, sizeof(IMAGE_SECTION_HEADER))) {
		return nullptr;
	}
	return hdr_ptr;
}

IMAGE_SECTION_HEADER* ArtefactScanner::findSectionsHdr(MemPageData &memPage)
{
	BYTE *hdr_ptr = findSecByPatterns(memPage);
	if (!hdr_ptr) {
		return nullptr;
	}
	DWORD charact = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	if (!is_valid_section(memPage.getLoadedData(), memPage.getLoadedSize(), hdr_ptr, charact)) {
		return nullptr;
	}
	// is it really the first section?
	IMAGE_SECTION_HEADER *first_sec = get_first_section(memPage.getLoadedData(), memPage.getLoadedSize(), (IMAGE_SECTION_HEADER*) hdr_ptr);
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
	//sanity checks of machine and optional header size:
	size_t opt_hdr_size = 0;
	if (hdr_candidate->Machine == IMAGE_FILE_MACHINE_I386) {
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER32);
	}
	else if (hdr_candidate->Machine == IMAGE_FILE_MACHINE_AMD64) {
		opt_hdr_size = sizeof(IMAGE_OPTIONAL_HEADER64);
	}
	else {
		// wrong machine ID
		return false;
	}

	if (hdr_candidate->SizeOfOptionalHeader < opt_hdr_size) {
		return false;
	}
	if (hdr_candidate->SizeOfOptionalHeader > PAGE_SIZE) {
		return false;
	}
	if (!peconv::validate_ptr(loadedData, loadedSize, hdr_candidate, 
		sizeof(IMAGE_FILE_HEADER) + hdr_candidate->SizeOfOptionalHeader))
	{
		return false;
	}
	//check characteristics:
	if (charact != 0 && (hdr_candidate->Characteristics & charact) == 0) {
		return false;
	}
	return true;
}

IMAGE_FILE_HEADER* ArtefactScanner::findNtFileHdr(BYTE* loadedData, size_t loadedSize)
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
	archs[ARCH_32B] = IMAGE_FILE_MACHINE_I386;
	archs[ARCH_64B] = IMAGE_FILE_MACHINE_AMD64;

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
	return reinterpret_cast<IMAGE_FILE_HEADER*>(arch_ptr);
}

ULONGLONG ArtefactScanner::findMzPeHeader(MemPageData &memPage)
{
	if (!memPage.load()) {
		return PE_NOT_FOUND;
	}
	const size_t scan_size = memPage.getLoadedSize();
	BYTE* buffer_ptr = memPage.getLoadedData();

	const size_t minimal_size = sizeof(IMAGE_DOS_HEADER)
		+ sizeof(IMAGE_FILE_HEADER)
		+ sizeof(IMAGE_OPTIONAL_HEADER32);

	//scan only one page, not the full area
	for (size_t i = 0; i < scan_size; i++) {
		if ((scan_size - i) < minimal_size) {
			break;
		}
		if (peconv::get_nt_hrds(buffer_ptr + i, scan_size - i) != nullptr) {
			return  memPage.region_start + i;
		}
	}
	return PE_NOT_FOUND;
}

bool ArtefactScanner::findMzPe(ArtefactScanner::ArtefactsMapping &mapping)
{
	mapping.pe_image_base = findMzPeHeader(mapping.memPage);
	if (mapping.pe_image_base == PE_NOT_FOUND) {
		return false;
	}

	BYTE* loadedData = mapping.memPage.getLoadedData();
	size_t loadedSize = mapping.memPage.getLoadedSize();

	size_t offset = mapping.pe_image_base - memPage.region_start;
	mapping.nt_file_hdr = findNtFileHdr(loadedData + offset, loadedSize - offset);
	mapping.isMzPeFound = true;
	return true;
}

bool ArtefactScanner::setSecHdr(ArtefactScanner::ArtefactsMapping &aMap, IMAGE_SECTION_HEADER* _sec_hdr)
{
	if (_sec_hdr == nullptr) return false;

	MemPageData &memPage = aMap.memPage;
	BYTE* loadedData = aMap.memPage.getLoadedData();
	size_t loadedSize = aMap.memPage.getLoadedSize();

	// try to find NT header relative to the sections header:
	size_t nt_hdr_search_bound = size_t((ULONGLONG)_sec_hdr - (ULONGLONG)loadedData);

	//search before sections header:
	aMap.nt_file_hdr = findNtFileHdr(loadedData, nt_hdr_search_bound);
	if (aMap.nt_file_hdr) {
		//found relative NT file header before, validation passed
		aMap.sec_hdr = _sec_hdr;

		if (!aMap.pe_image_base) {
			aMap.pe_image_base = calcPeBase(memPage, (BYTE*)aMap.nt_file_hdr);
		}
		return true;
	}

	//validate by counting the sections:
	size_t count = count_section_hdrs(loadedData, loadedSize, _sec_hdr);
	if (count == 0) {
		// sections header didn't passed validation
		return false;
	}
	aMap.sec_hdr = _sec_hdr;
	if (!aMap.pe_image_base) {
		aMap.pe_image_base = calcPeBase(memPage, (BYTE*)aMap.sec_hdr);
	}
	return true;
}

bool ArtefactScanner::setNtFileHdr(ArtefactScanner::ArtefactsMapping &aMap, IMAGE_FILE_HEADER* _nt_hdr)
{
	if (_nt_hdr == nullptr) return false;

	aMap.nt_file_hdr = _nt_hdr;
	
	MemPageData &memPage = aMap.memPage;
	BYTE* loadedData = aMap.memPage.getLoadedData();
	size_t loadedSize = aMap.memPage.getLoadedSize();

	size_t nt_offset = size_t((ULONGLONG)aMap.nt_file_hdr - (ULONGLONG)loadedData);

	//calculate sections header offset from FileHeader:
	const size_t headers_size = aMap.nt_file_hdr->SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER);
	size_t sec_hdr_offset = headers_size + nt_offset;

	if (!aMap.sec_hdr) {
		//sections headers are not set yet, try to detect them basing on File Header:
		IMAGE_SECTION_HEADER *sec_hdr = (IMAGE_SECTION_HEADER*)((ULONGLONG)loadedData + sec_hdr_offset);
		setSecHdr(aMap, sec_hdr);
		return true;
	}
	//validate sections headers:
	size_t found_offset = (ULONGLONG)aMap.sec_hdr - (ULONGLONG)loadedData;
	if (sec_hdr_offset != found_offset) {
		aMap.nt_file_hdr = nullptr;
		//it has sections headers detected, but not validly aligned:
		std::cout << "[WARNING] Sections header misaligned with FileHeader."
			<< "Expected offset" << std::hex << sec_hdr_offset << " vs real offset" << found_offset << std::endl;
		return false;
	}
	//validation passed:
	return true;
}

PeArtefacts* ArtefactScanner::generateArtefacts(ArtefactScanner::ArtefactsMapping &aMap)
{
	MemPageData &memPage = aMap.memPage;
	BYTE* loadedData = aMap.memPage.getLoadedData();
	size_t loadedSize = aMap.memPage.getLoadedSize();

	if (!aMap.sec_hdr) {
		// if sections headers not found, don't continue
		return nullptr;
	}

	PeArtefacts *peArt = new PeArtefacts();
	peArt->regionStart =  memPage.region_start;
	peArt->isMzPeFound = aMap.isMzPeFound;

	peArt->secHdrsOffset = size_t((ULONGLONG)aMap.sec_hdr - (ULONGLONG)loadedData);
	peArt->secCount = count_section_hdrs(loadedData, loadedSize, aMap.sec_hdr);

	// if File Header found, use it to validate or find sections headers:
	if (aMap.nt_file_hdr) {
		peArt->ntFileHdrsOffset = size_t((ULONGLONG)aMap.nt_file_hdr - (ULONGLONG)loadedData);;
	}
	if (!aMap.pe_image_base) {
		aMap.pe_image_base = calcPeBase(memPage, (BYTE*)aMap.sec_hdr);
	}
	peArt->peBaseOffset = size_t(aMap.pe_image_base - memPage.region_start);
	peArt->calculatedImgSize = calcImageSize(memPage, aMap.sec_hdr, aMap.pe_image_base);
	return peArt;
}

PeArtefacts* ArtefactScanner::findArtefacts(MemPageData &memPage)
{
	ArtefactsMapping aMap(memPage);
	findMzPe(aMap);

	//first try to find section headers:
	IMAGE_SECTION_HEADER *sec_hdr = findSectionsHdr(memPage);
	if (sec_hdr) {
		setSecHdr(aMap, sec_hdr);
	}

	if (!aMap.foundAny()) {
		//std::cout << "Not found!" << std::endl;
		//neither sections header nor file header found
		return nullptr;
	}

	//validate the header and search sections on its base:
	setNtFileHdr(aMap, aMap.nt_file_hdr);

	//generate aftefacts:
	return generateArtefacts(aMap);
}

PeArtefacts* ArtefactScanner::findInPrevPages(ULONGLONG addr_start, ULONGLONG addr_stop)
{
	deletePrevPage();
	PeArtefacts* peArt = nullptr;
	ULONGLONG next_addr = addr_stop - PAGE_SIZE;
	do {
		if (next_addr < addr_start) {
			break;
		}
		this->prevMemPage = new MemPageData(this->processHandle, next_addr);
		peArt = findArtefacts(*prevMemPage);
		if (peArt) {
			break;
		}
		next_addr -= (this->prevMemPage->region_start - PAGE_SIZE);
		deletePrevPage();
	} while (true);

	return peArt;
}

ArtefactScanReport* ArtefactScanner::scanRemote()
{
	deletePrevPage();

	bool is_damaged_pe = false;
	// it may still contain a damaged PE header...
	ULONGLONG region_start = memPage.region_start;
	MemPageData *artPagePtr = &memPage;

	PeArtefacts *peArt = findArtefacts(memPage);
	if (!peArt  && (region_start > memPage.alloc_base)) {
		peArt = findInPrevPages(memPage.alloc_base, memPage.region_start);
		if (prevMemPage) {
			artPagePtr = prevMemPage;
			region_start = prevMemPage->region_start;
		}
	}
	if (!peArt) {
		//no artefacts found
		return nullptr;
	}
	const size_t region_size = size_t(memPage.region_end - region_start);

	ArtefactScanReport *my_report = new ArtefactScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS, *peArt);
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;

	delete peArt;
	return my_report;
}
