#include "artefact_scanner.h"

#include "../utils/artefacts_util.h"
#include "../utils/workingset_enum.h"

#include "peconv.h"
#include "peconv/fix_imports.h"

size_t calc_offset(MemPageData &memPage, LPVOID field)
{
	if (!field) return INVALID_OFFSET;

	BYTE* loadedData = memPage.getLoadedData();
	size_t loadedSize = memPage.getLoadedSize();
	if (!peconv::validate_ptr(loadedData, loadedSize, field, sizeof(BYTE))) {
		return INVALID_OFFSET;
	}
	return size_t((ULONG_PTR)field - (ULONG_PTR)loadedData);
}

size_t calc_sec_hdrs_offset(MemPageData &memPage, IMAGE_FILE_HEADER* nt_file_hdr)
{
	size_t opt_hdr_size = nt_file_hdr->SizeOfOptionalHeader;
	if (opt_hdr_size == 0) {
		//try casual values
		bool is64bit = (nt_file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64) ? true : false;
		opt_hdr_size = is64bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
	}
	const size_t headers_size = opt_hdr_size + sizeof(IMAGE_FILE_HEADER);
	size_t nt_offset = calc_offset(memPage, nt_file_hdr);
	size_t sec_hdr_offset = headers_size + nt_offset;
	return sec_hdr_offset;
}

size_t calc_nt_hdr_offset(MemPageData &memPage, IMAGE_SECTION_HEADER* first_sec, bool is64bit = true)
{
	size_t sec_hdr_offset = calc_offset(memPage, first_sec);
	if (sec_hdr_offset == INVALID_OFFSET) {
		return INVALID_OFFSET;
	}
	size_t opt_hdr_size = is64bit ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
	const size_t headers_size = opt_hdr_size + sizeof(IMAGE_FILE_HEADER);
	size_t nt_offset = sec_hdr_offset - headers_size;
	return nt_offset;
}


bool validate_hdrs_alignment(MemPageData &memPage, IMAGE_FILE_HEADER *nt_file_hdr, IMAGE_SECTION_HEADER* _sec_hdr)
{
	if (!_sec_hdr) return false;
	if (!nt_file_hdr) return false;

	size_t sec_offset_hdrs = calc_sec_hdrs_offset(memPage, nt_file_hdr);
	size_t sec_offset = calc_offset(memPage, _sec_hdr);
	if (sec_offset_hdrs != sec_offset) {
		return false;
	}
	return true;
}

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

ULONGLONG ArtefactScanner::calcPeBase(MemPageData &memPage, LPVOID sec_hdr)
{
	size_t hdrs_offset = calc_offset(memPage, sec_hdr);
	if (hdrs_offset == INVALID_OFFSET) {
		std::cout << "Invalid sec_hdr_offset\n";
		return 0;
	}
	size_t full_pages = hdrs_offset / PAGE_SIZE;
	std::cout << "Full pages: " << std::dec << full_pages << std::endl;
	return memPage.region_start + (full_pages * PAGE_SIZE);
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

BYTE* ArtefactScanner::findSecByPatterns(BYTE *search_ptr, const size_t max_search_size)
{
	if (!memPage.load()) {
		return nullptr;
	}
	const DWORD charact = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
	//find sections table
	char sec_name[] = ".text";
	BYTE *hdr_ptr = find_pattern(search_ptr, max_search_size, (BYTE*)sec_name, strlen(sec_name));
	if (hdr_ptr) {
		// if the section was found by name, check if it has valid characteristics:
		if (is_valid_section(search_ptr, max_search_size, hdr_ptr, charact)) {
			return hdr_ptr;
		}
		hdr_ptr = nullptr;
	}
	// try another pattern
	BYTE sec_ending[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x60 // common characteristics
	};
	const size_t sec_ending_size = sizeof(sec_ending);
	hdr_ptr = find_pattern(search_ptr, max_search_size, sec_ending, sec_ending_size);
	if (!hdr_ptr) {
		return nullptr;
	}
	size_t offset_to_bgn = sizeof(IMAGE_SECTION_HEADER) - sec_ending_size;
	hdr_ptr -= offset_to_bgn;
	if (!peconv::validate_ptr(search_ptr, max_search_size, hdr_ptr, sizeof(IMAGE_SECTION_HEADER))) {
		return nullptr;
	}
	if (is_valid_section(search_ptr, max_search_size, hdr_ptr, charact)) {
		return hdr_ptr;
	}
	return nullptr;
}

IMAGE_SECTION_HEADER* ArtefactScanner::findSectionsHdr(MemPageData &memPage, const size_t max_search_size, const size_t search_offset)
{
	BYTE *search_ptr = search_offset + memPage.getLoadedData();
	if (!memPage.validatePtr(search_ptr, max_search_size)) {
		return nullptr;
	}
	BYTE *hdr_ptr = findSecByPatterns(search_ptr, max_search_size);
	if (!hdr_ptr) {
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
	if (hdr_candidate->SizeOfOptionalHeader > PAGE_SIZE) {
		return false;
	}
	if (!peconv::validate_ptr(loadedData, loadedSize, hdr_candidate, 
		sizeof(IMAGE_FILE_HEADER) + opt_hdr_size))
	{
		return false;
	}
	if (hdr_candidate->SizeOfOptionalHeader == opt_hdr_size) {
		return true;
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
		std::cout << "No architecture pattern found...\n";
		return nullptr;
	}
	DWORD charact = IMAGE_FILE_EXECUTABLE_IMAGE;
	if (my_arch == ARCH_32B) {
		charact |= IMAGE_FILE_32BIT_MACHINE;
	}
	else {
		charact |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
	}
	std::cout << "Found NT header, validating...\n";
	if (!is_valid_file_hdr(loadedData, loadedSize, arch_ptr, charact)) {
		return nullptr;
	}
	return reinterpret_cast<IMAGE_FILE_HEADER*>(arch_ptr);
}

IMAGE_DOS_HEADER* ArtefactScanner::findMzPeHeader(MemPageData &memPage, const size_t search_offset)
{
	if (!memPage.load()) {
		return nullptr;
	}
	if (memPage.getLoadedSize() <= search_offset) {
		return nullptr;
	}
	const size_t scan_size = memPage.getLoadedSize() - search_offset;
	BYTE* buffer_ptr = memPage.getLoadedData() + search_offset;
	if (!memPage.validatePtr(buffer_ptr, scan_size)) {
		return nullptr;
	}
	const size_t minimal_size = sizeof(IMAGE_DOS_HEADER)
		+ sizeof(IMAGE_FILE_HEADER)
		+ sizeof(IMAGE_OPTIONAL_HEADER32);

	//scan only one page, not the full area
	for (size_t i = 0; i < scan_size; i++) {
		if ((scan_size - i) < minimal_size) {
			break;
		}
		BYTE *dos_hdr = peconv::get_nt_hrds(buffer_ptr + i, scan_size - i);
		if (dos_hdr != nullptr) {
			return (IMAGE_DOS_HEADER*)(buffer_ptr + i);
		}
	}
	return nullptr;
}

bool ArtefactScanner::findMzPe(ArtefactScanner::ArtefactsMapping &aMap, const size_t search_offset)
{
	IMAGE_DOS_HEADER* dos_hdr = findMzPeHeader(aMap.memPage, search_offset);
	if (!dos_hdr) {
		return false;
	}
	if (!aMap.memPage.validatePtr(dos_hdr, sizeof(IMAGE_DOS_HEADER))) {
		return false;
	}
	if (setMzPe(aMap, dos_hdr)) {
		aMap.isMzPeFound = true;
	}
	return true;
}

bool ArtefactScanner::setMzPe(ArtefactsMapping &aMap, IMAGE_DOS_HEADER* _dos_hdr)
{
	if (!_dos_hdr) return false;

	aMap.dos_hdr = _dos_hdr;

	size_t dos_hdr_offset = calc_offset(aMap.memPage, aMap.dos_hdr);
	aMap.pe_image_base = aMap.memPage.region_start + dos_hdr_offset;

	IMAGE_NT_HEADERS32* pe_hdrs = (IMAGE_NT_HEADERS32*)((ULONGLONG)_dos_hdr + _dos_hdr->e_lfanew);
	if (!aMap.memPage.validatePtr(pe_hdrs, sizeof(IMAGE_NT_HEADERS32)))
	{
		return false;
	}
	setNtFileHdr(aMap, &pe_hdrs->FileHeader);
	return true;
}

bool ArtefactScanner::setSecHdr(ArtefactScanner::ArtefactsMapping &aMap, IMAGE_SECTION_HEADER* _sec_hdr)
{
	if (_sec_hdr == nullptr) return false;

	MemPageData &memPage = aMap.memPage;
	BYTE* loadedData = aMap.memPage.getLoadedData();
	size_t loadedSize = aMap.memPage.getLoadedSize();

	//validate by counting the sections:
	size_t count = count_section_hdrs(loadedData, loadedSize, _sec_hdr);
	if (count == 0) {
		std::cout << "Sections header didn't passed validation\n";
		// sections header didn't passed validation
		return false;
	}
	//if NT headers not found, search before sections header:
	if (!aMap.nt_file_hdr) {
		std::cout << "Trying to find NT header\n";
		// try to find NT header relative to the sections header:
		size_t sec_hdr_offset = calc_offset(aMap.memPage, _sec_hdr);
		if (sec_hdr_offset == INVALID_OFFSET) {
			return false;
		}
		std::cout << "Sections header at: " << std::hex << sec_hdr_offset << " passed validation\n";
		//if NT headers not found, search before sections header:
		if (!aMap.nt_file_hdr) {
			// try to find NT header relative to the sections header:
			size_t suggested_offset = calc_nt_hdr_offset(aMap.memPage, _sec_hdr);
			if (suggested_offset != INVALID_OFFSET) {
				aMap.nt_file_hdr = findNtFileHdr(loadedData + suggested_offset, sec_hdr_offset - suggested_offset);
			}
		}
	}
	if (aMap.nt_file_hdr && (ULONG_PTR)aMap.nt_file_hdr > (ULONG_PTR)_sec_hdr) {
		return false; //misaligned
	}
	aMap.sec_hdr = _sec_hdr;
	if (!aMap.pe_image_base) {
		aMap.pe_image_base = calcPeBase(aMap.memPage, (BYTE*)aMap.sec_hdr);
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

	size_t nt_offset = calc_offset(aMap.memPage, aMap.nt_file_hdr);
	//calculate sections header offset from FileHeader:
	if (!aMap.sec_hdr) {
		// set sections headers basing on File Header, do not validate yet
		size_t sec_hdr_offset = calc_sec_hdrs_offset(aMap.memPage, aMap.nt_file_hdr);
		aMap.sec_hdr = (IMAGE_SECTION_HEADER*)((ULONGLONG)loadedData + sec_hdr_offset);
		return true;
	}
	// sections headers were set before, validate if they match NT header:
	if (!validate_hdrs_alignment(aMap.memPage, aMap.nt_file_hdr, aMap.sec_hdr)) {
		aMap.nt_file_hdr = nullptr; // do not allow setting mismatching NT header
		std::cout << "[WARNING] Sections header misaligned with FileHeader." << std::endl;
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

	peArt->secHdrsOffset = calc_offset(memPage, aMap.sec_hdr);
	peArt->secCount = count_section_hdrs(loadedData, loadedSize, aMap.sec_hdr);

	// if File Header found, use it to validate or find sections headers:
	peArt->ntFileHdrsOffset = calc_offset(memPage, aMap.nt_file_hdr);
	std::cout << "NT offset: " << std::hex << peArt->ntFileHdrsOffset << std::endl;
	if (!aMap.pe_image_base) {
		aMap.pe_image_base = calcPeBase(aMap.memPage, (BYTE*)aMap.sec_hdr);
	}
	peArt->peBaseOffset = size_t(aMap.pe_image_base - memPage.region_start);
	peArt->calculatedImgSize = calcImageSize(memPage, aMap.sec_hdr, aMap.pe_image_base);

	if (aMap.nt_file_hdr) {
		peArt->isDll = ((aMap.nt_file_hdr->Characteristics & IMAGE_FILE_DLL) != 0);
	}
	return peArt;
}

PeArtefacts* ArtefactScanner::findArtefacts(MemPageData &memPage, size_t start_offset)
{
	if (!memPage.load()) {
		std::cerr << "Cannot read memory page!\n";
		return nullptr;
	}

	ArtefactsMapping bestMapping(memPage);

	for (size_t min_offset = start_offset; min_offset < memPage.getLoadedSize(); )
	{
		std::cout << "Searching DOS header, min_offset: " << std::hex << min_offset << std::endl;

		ArtefactsMapping aMap(memPage);
		if (findMzPe(aMap, min_offset)) {
			size_t dos_offset = calc_offset(memPage, aMap.dos_hdr);
			min_offset = dos_offset != INVALID_OFFSET ? dos_offset : min_offset;
			std::cout << "Setting minOffset: " << std::hex << min_offset << std::endl;
		}
		size_t max_section_search = memPage.getLoadedSize();
		if (aMap.nt_file_hdr) {
			size_t nt_offset = calc_offset(memPage, aMap.nt_file_hdr);
			if (nt_offset != INVALID_OFFSET && nt_offset > min_offset) {
				min_offset = nt_offset;
			}
			else {
				std::cout << "Wrong NT offset: " << std::hex << nt_offset << " vs min_offset: " << min_offset << std::endl;
			}
			//don't search in full module, only in the first mem page:
			max_section_search = PAGE_SIZE < memPage.getLoadedSize() ? PAGE_SIZE : memPage.getLoadedSize();
		}
		IMAGE_SECTION_HEADER *sec_hdr = findSectionsHdr(memPage, max_section_search - min_offset, min_offset);
		if (sec_hdr) {
			setSecHdr(aMap, sec_hdr);
			size_t sec_offset = calc_offset(memPage, aMap.sec_hdr);
			min_offset = (sec_offset != INVALID_OFFSET && min_offset > sec_offset) ? min_offset : sec_offset;
		}

		//validate the header and search sections on its base:
		if (setNtFileHdr(aMap, aMap.nt_file_hdr)) {
			if (setSecHdr(aMap, aMap.sec_hdr)) {
				//valid PE found:
				bestMapping = aMap;
				break;
			} else {
				std::cout << "[WARNING] Sections header didn't pass validation\n";
			}
		}
		else {
			std::cout << "[WARNING] NT header didn't pass validation\n";
		}
		
		bestMapping = (bestMapping < aMap) ? aMap : bestMapping;

		if (!aMap.foundAny()) {
			break;
		}
		min_offset++;
	}
	//use the best found set of artefacts:
	return generateArtefacts(bestMapping);
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
		peArt = findArtefacts(*prevMemPage, 0);
		if (peArt) {
			break;
		}
		next_addr -= (this->prevMemPage->region_start - PAGE_SIZE);
		deletePrevPage();
	} while (true);

	return peArt;
}

bool ArtefactScanner::hasShellcode(HMODULE region_start, size_t region_size, PeArtefacts &peArt)
{
	bool is_shellcode = false;
	if (peArt.peBaseOffset > 0) {
		// the total region is bigger than the PE
		is_shellcode = true;
	}
	size_t pe_region_size = peArt.calculatedImgSize + peArt.peBaseOffset;
	if (region_size > peArt.calculatedImgSize) {
		// the total region is bigger than the PE
		is_shellcode = true;
	}
	return is_shellcode;
}

ArtefactScanReport* ArtefactScanner::scanRemote()
{
	deletePrevPage();

	bool is_damaged_pe = false;
	// it may still contain a damaged PE header...
	ULONGLONG region_start = memPage.region_start;
	this->artPagePtr = &memPage;

	PeArtefacts *peArt = findArtefacts(memPage, 0);
	if (!peArt  && (region_start > memPage.alloc_base)) {
		peArt = findInPrevPages(memPage.alloc_base, memPage.region_start);
		if (prevMemPage) {
			this->artPagePtr = prevMemPage;
			region_start = prevMemPage->region_start;
		}
	}
	if (!peArt) {
		//no artefacts found
		return nullptr;
	}
	const size_t region_size = size_t(memPage.region_end - region_start);

	ArtefactScanReport *my_report = new ArtefactScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS, *peArt);
	my_report->protection = memPage.protection;
	my_report->has_shellcode = hasShellcode((HMODULE)region_start, region_size, *peArt);
	delete peArt;
	return my_report;
}
