#include "artefact_scanner.h"
/*
#include "../utils/path_converter.h"
#include "../utils/workingset_enum.h"
*/
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
		std::cout << "The section " << hdr_candidate->Name << " NOT  valid, charact:" << std::hex << hdr_candidate->Characteristics << std::endl;
		return false;
	}
	std::cout << "The section " << hdr_candidate->Name << " is valid!" << std::endl;
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
DWORD calc_image_size(BYTE *loadedData, size_t loadedSize, IMAGE_SECTION_HEADER *hdr_ptr)
{
	DWORD max_addr = 0;
	IMAGE_SECTION_HEADER* curr_sec = hdr_ptr;
	do {
		if (!is_valid_section(loadedData, loadedSize, (BYTE*)curr_sec, IMAGE_SCN_MEM_READ)) {
			break;
		}
		DWORD sec_max = curr_sec->VirtualAddress + curr_sec->Misc.VirtualSize;
		max_addr = (sec_max > max_addr) ? sec_max : max_addr;
		curr_sec++;
	} while (true);

	return max_addr;
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

MemPageScanReport* ArtefactScanner::scanRemote()
{
	bool is_damaged_pe = false;
	// it may still contain a damaged PE header...
	ULONGLONG sec_hdr_va = 0;
	size_t sec_count = 0;
	DWORD calculated_img_size = 0;
	IMAGE_SECTION_HEADER* sec_hdr = findSectionsHdr(memPage);
	if (sec_hdr) {

		is_damaged_pe = true;
		sec_count = count_section_hdrs(memPage.loadedData, memPage.loadedSize, sec_hdr);
		calculated_img_size = calc_image_size(memPage.loadedData, memPage.loadedSize, sec_hdr);
		sec_hdr_va = ((ULONGLONG)sec_hdr - (ULONGLONG)memPage.loadedData) + memPage.region_start;
	}

	ULONGLONG region_start = memPage.region_start;
	// check a mempage before the current one:
	if (memPage.region_start > memPage.alloc_base) {
		MemPageData prevMemPage(this->processHandle, memPage.alloc_base);
		sec_hdr = findSectionsHdr(prevMemPage);
		if (sec_hdr) {
			std::cout << "The detected shellcode is probably a corrupt PE" << std::endl;
			is_damaged_pe = true;
			region_start = prevMemPage.region_start;
			sec_count = count_section_hdrs(prevMemPage.loadedData, prevMemPage.loadedSize, sec_hdr);
			calculated_img_size = calc_image_size(prevMemPage.loadedData, prevMemPage.loadedSize, sec_hdr);
			sec_hdr_va = ((ULONGLONG)sec_hdr - (ULONGLONG)prevMemPage.loadedData) + prevMemPage.region_start;
		}
	}
	if (!is_damaged_pe) {
		return nullptr;
	}
	//TODO: differentiate the raport: shellcode vs PE
	const size_t region_size = size_t(memPage.region_end - region_start);
	MemPageScanReport *my_report = new MemPageScanReport(processHandle, (HMODULE)region_start, region_size, SCAN_SUSPICIOUS);
	my_report->is_executable = true;
	my_report->is_manually_loaded = !memPage.is_listed_module;
	my_report->protection = memPage.protection;
	my_report->is_shellcode = true;
	if (is_damaged_pe) {
		if (calculated_img_size > region_size) {
			my_report->moduleSize = calculated_img_size;
		}
		my_report->sections_count = sec_count;
		my_report->hdr_candidate = sec_hdr_va;
	}
	return my_report;
}
