#include "artefact_scanner.h"

#include "../utils/artefacts_util.h"
#include "../utils/workingset_enum.h"

#include <peconv.h>

using namespace pesieve;
using namespace pesieve::util;

namespace pesieve {
	namespace util {

		size_t calc_offset(MemPageData &memPage, LPVOID field)
		{
			if (!field) return INVALID_OFFSET;

			const BYTE* loadedData = memPage.getLoadedData();
			const size_t loadedSize = memPage.getLoadedSize();
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
				std::cout << std::hex << "sec_offset_hdrs: " << sec_offset_hdrs << " vs: " << sec_offset << "\n";

				return false;
			}
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

		IMAGE_SECTION_HEADER* get_first_section(BYTE *loadedData, size_t loadedSize, IMAGE_SECTION_HEADER *hdr_ptr)
		{
			IMAGE_SECTION_HEADER* prev_sec = hdr_ptr;
			do {
				if (!is_valid_section(loadedData, loadedSize, (BYTE*)prev_sec, IMAGE_SCN_MEM_READ)) {
					break;
				}
				hdr_ptr = prev_sec;
				prev_sec--;
			} while (true);

			return hdr_ptr;
		}

	}; //namespace util
}; // namespace pesieve

bool pesieve::is_valid_section(BYTE *loadedData, size_t loadedSize, BYTE *hdr_ptr, DWORD charact)
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
		////std::cout << "The section " << hdr_candidate->Name << " NOT  valid, charact:" << std::hex << hdr_candidate->Characteristics << std::endl;
		return false;
	}
	////std::cout << "The section " << hdr_candidate->Name << " is valid!" << std::endl;
	return true;
}

ULONGLONG pesieve::ArtefactScanner::_findMZoffset(MemPageData &memPage, LPVOID sec_hdr)
{
	size_t hdrs_offset = calc_offset(memPage, sec_hdr);
	if (hdrs_offset == INVALID_OFFSET) {
		return INVALID_OFFSET;
	}
	
	const BYTE mz_sig[] = "MZ\x90";

	BYTE *min_search = memPage.getLoadedData();
	BYTE *start_ptr = min_search + hdrs_offset - sizeof(mz_sig);
	size_t space = PAGE_SIZE;
	//std::cout << "Searching the MZ header starting from: " << std::hex << hdrs_offset << "\n";
	for (BYTE *search_ptr = start_ptr; search_ptr >= min_search && space > 0; search_ptr--, space--) {
		if ((search_ptr[0] == mz_sig[0] && search_ptr[1] == mz_sig[1] )
			&& (search_ptr[2] == mz_sig[2] || search_ptr[2] == 0))
		{
			//std::cout << "MZ header found!\n";
			return calc_offset(memPage, search_ptr);
		}
	}
	//std::cout << "MZ header not found :(\n";
	return INVALID_OFFSET;
}

ULONGLONG pesieve::ArtefactScanner::calcPeBase(MemPageData &memPage, LPVOID sec_hdr)
{
	ULONGLONG found_mz = _findMZoffset(memPage, sec_hdr);
	if (found_mz != INVALID_OFFSET) {
		return memPage.region_start + found_mz;
	}
	
	size_t hdrs_offset = calc_offset(memPage, sec_hdr);
	if (hdrs_offset == INVALID_OFFSET) {
		//std::cout << "Invalid sec_hdr_offset\n";
		return 0;
	}
	//search by stub patterns
	size_t search_start = (hdrs_offset > PAGE_SIZE) ? hdrs_offset - PAGE_SIZE: 0;
	IMAGE_DOS_HEADER *dos_hdr = findDosHdrByPatterns(memPage, search_start, hdrs_offset);
	size_t dos_offset = calc_offset(memPage, dos_hdr);
	if (dos_offset != INVALID_OFFSET) {
		return memPage.region_start + dos_offset;
	}

	//WARNING: this will be inacurate in cases if the PE is not aligned to the beginning of the page
	size_t full_pages = hdrs_offset / PAGE_SIZE;
	//std::cout << "Full pages: " << std::dec << full_pages << std::endl;
	return memPage.region_start + (full_pages * PAGE_SIZE);
}

size_t pesieve::ArtefactScanner::calcImgSize(HANDLE processHandle, HMODULE modBaseAddr, BYTE* headerBuffer, size_t headerBufferSize, IMAGE_SECTION_HEADER *hdr_ptr)
{
	if (!hdr_ptr) {
		hdr_ptr = peconv::get_section_hdr(headerBuffer, headerBufferSize, 0);
		if (!hdr_ptr) return peconv::fetch_region_size(processHandle, (PBYTE)modBaseAddr);
	}

	DWORD max_addr = 0;

	const ULONGLONG main_base = peconv::fetch_alloc_base(processHandle, (PBYTE)modBaseAddr);
	for (IMAGE_SECTION_HEADER* curr_sec = hdr_ptr; ; curr_sec++)
	{
		//we don't know the number of sections, so we should validate each one
		if (!is_valid_section(headerBuffer, headerBufferSize, (BYTE*)curr_sec, 0)) {
			break;
		}
		if (curr_sec->Misc.VirtualSize == 0 || curr_sec->VirtualAddress == 0) {
			continue; //skip empty sections
		}

		const DWORD sec_rva = curr_sec->VirtualAddress;

		MEMORY_BASIC_INFORMATION page_info = { 0 };
		if (!peconv::fetch_region_info(processHandle, (PBYTE)((ULONG_PTR)modBaseAddr + sec_rva), page_info)) {
			break;
		}
		if ((ULONG_PTR)page_info.AllocationBase != main_base) {
			//it can happen if the PE is in a RAW format instead of Virtual
#ifdef _DEBUG
			std::cout << "[!] Mismatch: region_base : " << std::hex << page_info.AllocationBase << " while main base: " << main_base << "\n";
#endif
			break; // out of scope
		}
		if (page_info.Type == 0 || page_info.Protect == 0) {
			break; //invalid type, skip it
		}
		if ((page_info.State & MEM_COMMIT) == 0) {
			continue; //skip non-commited pages
		}
		if (sec_rva > max_addr) {
			max_addr = sec_rva;
		}
	}

	size_t last_sec_size = peconv::fetch_region_size(processHandle, (PBYTE)((ULONG_PTR)modBaseAddr + max_addr));
	size_t total_size = max_addr + last_sec_size;
#ifdef _DEBUG
	std::cout << "Image: " << std::hex << (ULONGLONG)modBaseAddr << " Size:" << std::hex << total_size << " max_addr: " << max_addr << std::endl;
#endif
	return total_size;
}

//calculate image size basing on the sizes of sections
size_t pesieve::ArtefactScanner::calcImageSize(MemPageData &memPage, IMAGE_SECTION_HEADER *hdr_ptr, ULONGLONG pe_image_base)
{
	return ArtefactScanner::calcImgSize(this->processHandle, (HMODULE)pe_image_base, memPage.getLoadedData(), memPage.getLoadedSize(), hdr_ptr);
}

IMAGE_DOS_HEADER* pesieve::ArtefactScanner::findDosHdrByPatterns(MemPageData &memPage, const size_t start_offset, size_t hdrs_offset)
{
	BYTE* data = memPage.getLoadedData();
	if (!data) return nullptr;

	BYTE *search_ptr = data + start_offset;
	BYTE *max_search = search_ptr + hdrs_offset;

	size_t max_search_size = max_search - search_ptr;
	if (!memPage.validatePtr(search_ptr, max_search_size)) {
		return nullptr;
	}
	IMAGE_DOS_HEADER* dos_hdr = _findDosHdrByPatterns(search_ptr, max_search_size);
	const bool is_dos_valid = memPage.validatePtr(dos_hdr, sizeof(IMAGE_DOS_HEADER));
	if (is_dos_valid) {
		return dos_hdr;
	}
	return nullptr;
}

IMAGE_DOS_HEADER* pesieve::ArtefactScanner::_findDosHdrByPatterns(BYTE *search_ptr, const size_t max_search_size)
{
	if (!memPage.load()) {
		return nullptr;
	}

	const size_t patterns_count = 2;
	const size_t pattern_size = 14;
	BYTE stub_patterns[patterns_count][pattern_size] = { // common beginnnig of DOS stubs
		{
			0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4,
			0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C,
			0xCD, 0x21
		},
		{
			0xBA, 0x10, 0x00, 0x0E, 0x1F, 0xB4, 
			0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C,
			0xCD, 0x21
		}
	};

	const size_t dos_hdr_size = sizeof(IMAGE_DOS_HEADER);

	BYTE *stub_ptr = nullptr;
	IMAGE_DOS_HEADER *dos_ptr = nullptr;
	for (size_t i = 0; i < patterns_count; i++) {
		BYTE *pattern = stub_patterns[i];
		stub_ptr = find_pattern(search_ptr, max_search_size, pattern, pattern_size);
		if (!stub_ptr) {
			continue;
		}
		size_t offset_to_bgn = sizeof(IMAGE_DOS_HEADER);
		if ((ULONG_PTR)stub_ptr < offset_to_bgn) {
			return nullptr;
		}
		dos_ptr = (IMAGE_DOS_HEADER*)((ULONG_PTR)stub_ptr - offset_to_bgn);
		if (!peconv::validate_ptr(search_ptr, max_search_size, dos_ptr, sizeof(IMAGE_DOS_HEADER))) {
			continue;
		}
		return dos_ptr;
	}
	return nullptr;
}

bool pesieve::ArtefactScanner::_validateSecRegions(MemPageData &memPage, LPVOID sec_hdr, size_t sec_count, ULONGLONG pe_image_base, bool is_virtual)
{
	if (!sec_hdr || !sec_count) {
		return false;
	}
	MEMORY_BASIC_INFORMATION module_start_info = { 0 };
	if (!peconv::fetch_region_info(processHandle, (BYTE*)pe_image_base, module_start_info)) {
		return false;
	}
	IMAGE_SECTION_HEADER* curr_sec = (IMAGE_SECTION_HEADER*)sec_hdr;

	for (size_t i = 0; i < sec_count; i++, curr_sec++) {
		if (curr_sec->VirtualAddress == 0) continue;

		ULONG sec_start = is_virtual ? curr_sec->VirtualAddress : curr_sec->PointerToRawData;
		ULONGLONG last_sec_addr = pe_image_base + sec_start;

		MEMORY_BASIC_INFORMATION page_info = { 0 };
		if (!peconv::fetch_region_info(processHandle, (BYTE*)last_sec_addr, page_info)) {
#ifdef _DEBUG
			std::cout << std::hex << last_sec_addr << " couldn't fetch module info" << std::endl;
#endif
			return false;
		}
		if (page_info.AllocationBase != module_start_info.AllocationBase) {
#ifdef _DEBUG
			std::cout << "[-] SecBase mismatch: ";
			if (curr_sec->Name) {
				std::cout << curr_sec->Name;
			}
			std::cout << std::hex << i << " section: " << last_sec_addr << " alloc base: " << page_info.AllocationBase << " with module base: " << module_start_info.AllocationBase << std::endl;
#endif
			return false;
		}
	}
	return true;
}

bool pesieve::ArtefactScanner::_validateSecRegions(MemPageData &memPage, LPVOID sec_hdr, size_t sec_count)
{
	if (!memPage.getLoadedData() || !sec_hdr) {
		return 0;
	}
	ULONGLONG pe_image_base = this->calcPeBase(memPage, sec_hdr);
	bool has_non_zero = false;

	IMAGE_SECTION_HEADER* curr_sec = (IMAGE_SECTION_HEADER*)sec_hdr;
	for (size_t i = 0; i < sec_count; i++, curr_sec++) {
		if (curr_sec->VirtualAddress && curr_sec->Misc.VirtualSize) {
			has_non_zero = true;
		}
	}
	if (!has_non_zero) return false;

	//validate Virtual Sections alignment
	bool is_ok = _validateSecRegions(memPage, sec_hdr, sec_count, pe_image_base, true);
	if (!is_ok) {
		//maybe it is raw?
		is_ok = _validateSecRegions(memPage, sec_hdr, sec_count, pe_image_base, false);
#ifdef _DEBUG
		if (!is_ok) {
			std::cout << "[-] Raw failed!\n";
		}
		else {
			std::cout << "[+] Raw OK!\n";
		}
#endif
	}
#ifdef _DEBUG
	else {
		std::cout << "[+] Virtual OK!\n";
	}
#endif
	return is_ok;
}

BYTE* pesieve::ArtefactScanner::_findSecByPatterns(BYTE *search_ptr, const size_t max_search_size)
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
	const size_t patterns_count = 2;
	const size_t pattern_size = sizeof(DWORD) * 4;
	BYTE charact_patterns[patterns_count][pattern_size] = { // common characteristics
		{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x20, 0x00, 0x00, 0x60
		},
		{
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x40, 0x00, 0x00, 0xC0
		}
	};

	for (size_t i = 0; i < patterns_count; i++) {
		BYTE *sec_ending = charact_patterns[i];
		const size_t sec_ending_size = pattern_size;
		hdr_ptr = find_pattern(search_ptr, max_search_size, sec_ending, sec_ending_size);
		if (!hdr_ptr) {
			continue;
		}
		size_t offset_to_bgn = sizeof(IMAGE_SECTION_HEADER) - sec_ending_size;
		hdr_ptr -= offset_to_bgn;
		if (!peconv::validate_ptr(search_ptr, max_search_size, hdr_ptr, sizeof(IMAGE_SECTION_HEADER))) {
			continue;
		}
		if (is_valid_section(search_ptr, max_search_size, hdr_ptr, charact)) {
			return hdr_ptr;
		}
	}
	return nullptr;
}

IMAGE_SECTION_HEADER* pesieve::ArtefactScanner::findSecByPatterns(MemPageData &memPage, const size_t max_search_size, const size_t search_offset)
{
	BYTE *search_ptr = search_offset + memPage.getLoadedData();
	if (!memPage.validatePtr(search_ptr, max_search_size)) {
		return nullptr;
	}
	BYTE *hdr_ptr = _findSecByPatterns(search_ptr, max_search_size);
	if (!hdr_ptr) {
		return nullptr;
	}
	// is it really the first section?
	IMAGE_SECTION_HEADER *first_sec = get_first_section(memPage.getLoadedData(), memPage.getLoadedSize(), (IMAGE_SECTION_HEADER*) hdr_ptr);
	if (!first_sec) {
		return nullptr;
	}
	size_t count = count_section_hdrs(memPage.getLoadedData(), memPage.getLoadedSize(), first_sec);
	if (!_validateSecRegions(memPage, first_sec, count)) {
#ifdef _DEBUG
		const ULONGLONG diff = (ULONGLONG)first_sec - (ULONGLONG)memPage.getLoadedData();
		std::cout << "[!] section header: " << std::hex << (ULONGLONG)memPage.region_start << " hdr at: " << diff << " : validation failed!\n";
#endif
		return nullptr;
	}
	return (IMAGE_SECTION_HEADER*)first_sec;
}

bool pesieve::is_valid_file_hdr(BYTE *loadedData, size_t loadedSize, BYTE *hdr_ptr, DWORD charact)
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

IMAGE_FILE_HEADER* pesieve::ArtefactScanner::findNtFileHdr(MemPageData &memPage, const size_t start_offset, size_t stop_offset)
{
	BYTE* const loadedData  = memPage.getLoadedData();
	size_t const loadedSize = memPage.getLoadedSize();
	size_t max_iter = 0; //UNLIMITED

	if (!loadedData) return nullptr;
	//std::cout << "Searching NT header, starting_offset = " << std::hex << start_offset << "\n";
	//normalize the stop_offset:
	if (stop_offset == INVALID_OFFSET || stop_offset == 0) {
		stop_offset = loadedSize;
		max_iter = 1;
	}
	if (stop_offset > loadedSize) {
		stop_offset = loadedSize;
	}
	//check the constraints:
	if (start_offset == INVALID_OFFSET
		|| start_offset >= loadedSize || stop_offset <= start_offset)
	{
		return nullptr;
	}

	BYTE* search_ptr = loadedData + start_offset;
	size_t search_size = loadedSize - start_offset;

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
		arch_ptr = find_pattern(search_ptr, search_size, (BYTE*)&archs[my_arch], sizeof(WORD), max_iter);
		if (arch_ptr) {
			break;
		}
	}
	if (!arch_ptr) {
		//std::cout << "No architecture pattern found...\n";
		return nullptr;
	}
	DWORD charact = IMAGE_FILE_EXECUTABLE_IMAGE;
	if (my_arch == ARCH_32B) {
		charact |= IMAGE_FILE_32BIT_MACHINE;
	}
	else {
		charact |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
	}
	//std::cout << "Found NT header, validating...\n";
	if (!is_valid_file_hdr(loadedData, loadedSize, arch_ptr, charact)) {
		return nullptr;
	}
	return reinterpret_cast<IMAGE_FILE_HEADER*>(arch_ptr);
}


IMAGE_DOS_HEADER* pesieve::ArtefactScanner::findMzPeHeader(MemPageData &memPage, const size_t search_offset)
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
		const size_t remaining_size = scan_size - i;
		if (remaining_size < minimal_size) {
			break;
		}
		const BYTE* pe_candidate = buffer_ptr + i;
		BYTE *nt_hdr = peconv::get_nt_hdrs(pe_candidate, remaining_size);
		if (nt_hdr != nullptr) {
			//it was possible to retrieve the NT header, so the PE candidate passed validation
			return (IMAGE_DOS_HEADER*)(pe_candidate);
		}
	}
	return nullptr;
}

bool pesieve::ArtefactScanner::findMzPe(ArtefactScanner::ArtefactsMapping &aMap, const size_t search_offset)
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

bool pesieve::ArtefactScanner::setMzPe(ArtefactsMapping &aMap, IMAGE_DOS_HEADER* _dos_hdr)
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

bool pesieve::ArtefactScanner::setSecHdr(ArtefactScanner::ArtefactsMapping &aMap, IMAGE_SECTION_HEADER* _sec_hdr)
{
	if (_sec_hdr == nullptr) return false;
	const size_t sec_hdr_offset = calc_offset(aMap.memPage, _sec_hdr);
	if (sec_hdr_offset == INVALID_OFFSET) {
		return false;
	}
	MemPageData &memPage = aMap.memPage;
	BYTE* loadedData = aMap.memPage.getLoadedData();
	size_t loadedSize = aMap.memPage.getLoadedSize();

	//validate by counting the sections:
	size_t count = count_section_hdrs(loadedData, loadedSize, _sec_hdr);
	if (count == 0) {
		//std::cout << "Sections header didn't passed validation\n";
		// sections header didn't passed validation
		return false;
	}
	//if NT headers not found, search before sections header:
	if (!aMap.nt_file_hdr) {
		// try to find NT header relative to the sections header:
		size_t suggested_nt_offset = calc_nt_hdr_offset(aMap.memPage, _sec_hdr, this->isProcess64bit);
		if (suggested_nt_offset != INVALID_OFFSET && (sec_hdr_offset >= suggested_nt_offset)) {
			aMap.nt_file_hdr = findNtFileHdr(aMap.memPage, suggested_nt_offset, sec_hdr_offset);
		}
	}
	if (aMap.nt_file_hdr && (ULONG_PTR)aMap.nt_file_hdr > (ULONG_PTR)_sec_hdr) {
		return false; //misaligned
	}
	aMap.sec_hdr = _sec_hdr;
	aMap.sec_count = count;
	if (!aMap.pe_image_base) {
		aMap.pe_image_base = calcPeBase(aMap.memPage, (BYTE*)aMap.sec_hdr);
	}
	return true;
}

bool pesieve::ArtefactScanner::setNtFileHdr(ArtefactScanner::ArtefactsMapping &aMap, IMAGE_FILE_HEADER* _nt_hdr)
{
	if (!_nt_hdr) return false;

	aMap.nt_file_hdr = _nt_hdr;
	
	MemPageData &memPage = aMap.memPage;
	BYTE* loadedData = aMap.memPage.getLoadedData();

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

PeArtefacts* pesieve::ArtefactScanner::generateArtefacts(ArtefactScanner::ArtefactsMapping &aMap)
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
	//std::cout << "NT offset: " << std::hex << peArt->ntFileHdrsOffset << std::endl;
	if (!aMap.pe_image_base) {
		aMap.pe_image_base = calcPeBase(aMap.memPage, (BYTE*)aMap.sec_hdr);
	}
	peArt->peBaseOffset = size_t(aMap.pe_image_base - memPage.region_start);
	peArt->calculatedImgSize = calcImageSize(memPage, aMap.sec_hdr, aMap.pe_image_base);

	if (aMap.nt_file_hdr) {
		peArt->isDll = ((aMap.nt_file_hdr->Characteristics & IMAGE_FILE_DLL) != 0);
	}

	if (aMap.nt_file_hdr && aMap.nt_file_hdr->Machine == IMAGE_FILE_MACHINE_I386) {
		aMap.is64bit = false;
	}
	else if (aMap.nt_file_hdr && aMap.nt_file_hdr->Machine == IMAGE_FILE_MACHINE_AMD64) {
		aMap.is64bit = true;
	}
	else {
		aMap.is64bit = this->isProcess64bit;
	}
	peArt->is64bit = aMap.is64bit;
	return peArt;
}

PeArtefacts* pesieve::ArtefactScanner::findArtefacts(MemPageData &_memPage, size_t start_offset)
{
	if (!_memPage.load()) {
		return nullptr;
	}

	ArtefactsMapping bestMapping(_memPage, this->isProcess64bit);

	for (size_t min_offset = start_offset; min_offset < _memPage.getLoadedSize(); min_offset++)
	{
		//std::cout << "Searching DOS header, min_offset: " << std::hex << min_offset << std::endl;

		ArtefactsMapping aMap(_memPage, this->isProcess64bit);
		//try to find the DOS header
		if (findMzPe(aMap, min_offset)) {
			const size_t dos_offset = calc_offset(_memPage, aMap.dos_hdr);
			min_offset = (dos_offset != INVALID_OFFSET) ? dos_offset : min_offset;
#ifdef _DEBUG
			std::cout << std::hex << "Page: " << aMap.memPage.start_va << " Found DOS Header at: " << dos_offset << "\n";
#endif
		}
		else {
#ifdef _DEBUG
			std::cout << std::hex << "Page: " << aMap.memPage.start_va << " Searching NT Header at: " << min_offset << "\n";
#endif
			IMAGE_FILE_HEADER *nt_hdr = findNtFileHdr(aMap.memPage, min_offset, _memPage.getLoadedSize());
			setNtFileHdr(aMap, nt_hdr);
		}

		//adjust constraints for further searches:
		size_t max_section_search = _memPage.getLoadedSize();
		if (aMap.nt_file_hdr) {
			const size_t nt_offset = calc_offset(_memPage, aMap.nt_file_hdr);
			if (nt_offset != INVALID_OFFSET && nt_offset > min_offset) {
				min_offset = nt_offset;
			}
			//don't search sections in full module, only in the first mem page after the NT header:
			max_section_search = (PAGE_SIZE < _memPage.getLoadedSize()) ? PAGE_SIZE : _memPage.getLoadedSize();
			if (max_section_search + min_offset <= _memPage.getLoadedSize()) {
				max_section_search += min_offset; //move the search window
			}
		}

		if (!setSecHdr(aMap, aMap.sec_hdr)) {
			//search sections by pattens:
			if (max_section_search > min_offset) {
				const size_t diff = max_section_search - min_offset;
				IMAGE_SECTION_HEADER *sec_hdr = findSecByPatterns(_memPage, diff, min_offset);
				setSecHdr(aMap, sec_hdr);
			}
		}
		if (aMap.sec_hdr) {
			const size_t sec_offset = calc_offset(_memPage, aMap.sec_hdr);
			if (sec_offset != INVALID_OFFSET && sec_offset > min_offset) {
				const size_t sections_area_size = aMap.sec_count * sizeof(IMAGE_SECTION_HEADER);
				min_offset = (sec_offset + sections_area_size);
#ifdef _DEBUG
				std::cout << "Setting minOffset to SecHdr end offset: " << std::hex << min_offset << "\n";
#endif
			}

			if (!aMap.dos_hdr) {
				const size_t start = (sec_offset > PAGE_SIZE) ? (sec_offset - PAGE_SIZE) : 0;
				//std::cout << "Searching DOS header by patterns " << std::hex << start << "\n";
				aMap.dos_hdr = findDosHdrByPatterns(aMap.memPage, start, sec_offset);
				if (aMap.dos_hdr && !aMap.nt_file_hdr) {
					IMAGE_NT_HEADERS32 *nt_ptr = (IMAGE_NT_HEADERS32*)((ULONG_PTR)aMap.dos_hdr + aMap.dos_hdr->e_lfanew);
#ifdef _DEBUG
					const size_t nt_offset = calc_offset(memPage, nt_ptr);
					std::cout << "Found PE offset: " << std::hex << aMap.dos_hdr->e_lfanew << " NT offset: " << nt_offset << "\n";
#endif
					if (aMap.memPage.validatePtr(nt_ptr, sizeof(IMAGE_NT_HEADERS32))) {
						setNtFileHdr(aMap, &nt_ptr->FileHeader);
					}
				}
			}
		}
		if (!setSecHdr(aMap, aMap.sec_hdr)) {
			aMap.sec_hdr = nullptr;
		}
		bestMapping = (bestMapping < aMap) ? aMap : bestMapping;

		//do not continue the search if no artefacts found:
		if (!aMap.foundAny()) break;

		// adjust minimal values:
		const size_t nt_offset = calc_offset(_memPage, aMap.nt_file_hdr);
		const size_t sec_offset = calc_offset(_memPage, aMap.sec_hdr);
		if (nt_offset != INVALID_OFFSET && nt_offset > min_offset) {
			min_offset = nt_offset;
		}
		if (sec_offset != INVALID_OFFSET && sec_offset > min_offset) {
			min_offset = sec_offset;
		}
	}
	if (bestMapping.getScore() <= 1) {
		return nullptr; // too low score	
	}
	//use the best found set of artefacts:
	return generateArtefacts(bestMapping);
}

PeArtefacts* pesieve::ArtefactScanner::findInPrevPages(ULONGLONG addr_start, ULONGLONG addr_stop)
{
	deletePrevPage();
	PeArtefacts* peArt = nullptr;
	ULONGLONG next_addr = addr_stop - PAGE_SIZE;
	do {
		if (next_addr < addr_start) {
			break;
		}
		const size_t area_size = size_t(addr_stop - next_addr);
		if (this->processReport.hasModuleContaining((ULONGLONG)next_addr, area_size)) {
			//std::cout << "Aready scanned: " << std::hex << next_addr << " size: " << area_size << "\n";
			break;
		}
		this->prevMemPage = new MemPageData(this->processHandle, this->pDetails.isReflection, next_addr, addr_stop);
		peArt = findArtefacts(*prevMemPage, 0);
		if (peArt) {
			break;
		}
		next_addr -= (this->prevMemPage->region_start - PAGE_SIZE);
		deletePrevPage();
	} while (true);

	return peArt;
}

bool pesieve::ArtefactScanner::hasShellcode(HMODULE region_start, size_t region_size, PeArtefacts &peArt)
{
	bool is_shellcode = false;
	if (peArt.peBaseOffset > 0) {
		// the total region is bigger than the PE
		is_shellcode = true;
	}
	if (region_size > peArt.calculatedImgSize) {
		// the total region is bigger than the PE
		is_shellcode = true;
	}
	return is_shellcode;
}

ArtefactScanReport* pesieve::ArtefactScanner::scanRemote()
{
	deletePrevPage();

	// it may still contain a damaged PE header...
	ULONGLONG region_start = memPage.region_start;
	this->artPagePtr = &memPage;

	PeArtefacts *peArt = findArtefacts(memPage, 0);
	if (!peArt && (region_start > memPage.alloc_base)) {
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

	ArtefactScanReport *my_report = new ArtefactScanReport((HMODULE)region_start, region_size, SCAN_SUSPICIOUS, *peArt);
	my_report->protection = memPage.protection;
	my_report->has_shellcode = hasShellcode((HMODULE)region_start, region_size, *peArt);
	delete peArt;
	return my_report;
}
