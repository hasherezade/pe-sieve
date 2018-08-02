#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "mempage_scanner.h"

bool is_valid_section(BYTE *loadedData, size_t loadedSize, BYTE *hdr_ptr, DWORD charact);

class PeArtefacts {
public:
	PeArtefacts() {
		region_start = 0;
		file_hdr_offset = 0;
		sec_hdr_offset = 0;
		sec_count = 0;
		calculated_img_size = 0;
	}

	LONGLONG region_start;
	ULONGLONG file_hdr_offset;
	ULONGLONG sec_hdr_offset;
	size_t sec_count;
	DWORD calculated_img_size;
};

class ArtefactScanReport : public MemPageScanReport
{
public:
	ArtefactScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, t_scan_status status, PeArtefacts &peArt)
		: MemPageScanReport(processHandle, _module, _moduleSize, status)
	{
		is_executable = true;
		is_manually_loaded = true;
		protection = 0;
		is_shellcode = true;
		sections_hdrs = 0;

		nt_file_hdr = 0;
		if (peArt.file_hdr_offset) {
			nt_file_hdr = peArt.file_hdr_offset + peArt.region_start;
		}
		sections_count = peArt.sec_count;
		sections_hdrs = peArt.sec_hdr_offset + peArt.region_start;

	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"artefacts_scan\" : ";
		outs << "{\n";
		MemPageScanReport::fieldsToJSON(outs);
		if (nt_file_hdr) {
			outs << ",\n";
			outs << "\"nt_file_hdr\" : ";
			outs << "\"" << std::hex << nt_file_hdr << "\"";
		}
		outs << ",\n";
		outs << "\"sections_hdrs\" : ";
		outs << "\"" << std::hex << sections_hdrs << "\"";
		outs << ",\n";
		outs << "\"sections_count\" : ";
		outs << std::hex << sections_count;
		
		outs << "\n}";
		return true;
	}

	ULONGLONG nt_file_hdr;
	ULONGLONG sections_hdrs;
	size_t sections_count;
};

class ArtefactScanner {
public:
	ArtefactScanner(HANDLE _procHndl, MemPageData &_memPageData)
		: processHandle(_procHndl), memPage(_memPageData)
	{
		prevMemPage = nullptr;
	}

	virtual ~ArtefactScanner()
	{
		if (prevMemPage) {
			delete prevMemPage;
		}
	}

	virtual ArtefactScanReport* scanRemote();
protected:
	PeArtefacts* findArtefacts(MemPageData &memPage);

	DWORD calcImageSize(MemPageData &memPage, IMAGE_SECTION_HEADER *hdr_ptr);

	BYTE* findNtFileHdr(BYTE* loadedData, size_t loadedSize);

	IMAGE_SECTION_HEADER* findSectionsHdr(MemPageData &memPageData);

	HANDLE processHandle;
	MemPageData &memPage;
	MemPageData *prevMemPage;
};
