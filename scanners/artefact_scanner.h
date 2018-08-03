#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "mempage_scanner.h"

#define INVALID_OFFSET (-1)

bool is_valid_section(BYTE *loadedData, size_t loadedSize, BYTE *hdr_ptr, DWORD charact);

class PeArtefacts {
public:
	PeArtefacts() {
		region_start = INVALID_OFFSET;
		file_hdr_offset = INVALID_OFFSET;
		sec_hdr_offset = INVALID_OFFSET;
		sec_count = 0;
		calculated_img_size = 0;
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		if (file_hdr_offset != INVALID_OFFSET) {
			outs << ",\n";
			outs << "\"nt_file_hdr\" : ";
			outs << "\"" << std::hex << file_hdr_offset << "\"";
		}
		outs << ",\n";
		outs << "\"sections_hdrs\" : ";
		outs << "\"" << std::hex << sec_hdr_offset << "\"";
		outs << ",\n";
		outs << "\"sections_count\" : ";
		outs << std::hex << sec_count;
		return true;
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
		: MemPageScanReport(processHandle, _module, _moduleSize, status),
		artefacts(peArt)
	{
		is_executable = true;
		is_manually_loaded = true;
		protection = 0;
		is_shellcode = true;
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"artefacts_scan\" : ";
		outs << "{\n";
		MemPageScanReport::fieldsToJSON(outs);
		artefacts.toJSON(outs);
		outs << "\n}";
		return true;
	}

	PeArtefacts artefacts;
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
		deletePrevPage();
	}

	virtual ArtefactScanReport* scanRemote();

protected:
	void deletePrevPage()
	{
		if (this->prevMemPage) {
			delete this->prevMemPage;
		}
		this->prevMemPage = nullptr;
	}

	PeArtefacts* findArtefacts(MemPageData &memPage);
	PeArtefacts* findInPrevPages(ULONGLONG addr_start, ULONGLONG addr_stop);

	DWORD calcImageSize(MemPageData &memPage, IMAGE_SECTION_HEADER *hdr_ptr);

	BYTE* findNtFileHdr(BYTE* loadedData, size_t loadedSize);
	BYTE* findSecByPatterns(MemPageData &memPage);
	IMAGE_SECTION_HEADER* findSectionsHdr(MemPageData &memPageData);

	HANDLE processHandle;
	MemPageData &memPage;
	MemPageData *prevMemPage;
};
