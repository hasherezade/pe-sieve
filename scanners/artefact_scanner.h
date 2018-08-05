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
		regionStart = INVALID_OFFSET;
		peBaseOffset = INVALID_OFFSET;
		ntFileHdrsOffset = INVALID_OFFSET;
		secHdrsOffset = INVALID_OFFSET;
		secCount = 0;
		calculatedImgSize = 0;
	}

	bool hasNtHdrs()
	{
		return (ntFileHdrsOffset != INVALID_OFFSET);
	}

	bool hasSectionHdrs()
	{
		return (secHdrsOffset != INVALID_OFFSET);
	}
	
	ULONGLONG peImageBase()
	{
		return this->peBaseOffset + this->regionStart;
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << ",\n";
		outs << "\"pe_base_offset\" : ";
		outs << "\"" << std::hex << peBaseOffset << "\"";
		if (hasNtHdrs()) {
			outs << ",\n";
			outs << "\"nt_file_hdr\" : ";
			outs << "\"" << std::hex << ntFileHdrsOffset << "\"";
		}
		outs << ",\n";
		outs << "\"sections_hdrs\" : ";
		outs << "\"" << std::hex << secHdrsOffset << "\"";
		outs << ",\n";
		outs << "\"sections_count\" : ";
		outs << std::hex << secCount;
		return true;
	}

	LONGLONG regionStart;
	size_t peBaseOffset; //offset from the regionStart (PE may not start at the first page of the region)
	size_t ntFileHdrsOffset; //offset from the regionStart
	size_t secHdrsOffset; //offset from the regionStart
	size_t secCount;
	size_t calculatedImgSize;
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

	ULONGLONG findMzPeHeader(MemPageData &memPage);

	PeArtefacts* findArtefacts(MemPageData &memPage);
	PeArtefacts* findInPrevPages(ULONGLONG addr_start, ULONGLONG addr_stop);

	ULONGLONG calcPeBase(MemPageData &memPage, BYTE *hdr_ptr);
	size_t calcImageSize(MemPageData &memPage, IMAGE_SECTION_HEADER *hdr_ptr, ULONGLONG pe_image_base);

	IMAGE_FILE_HEADER* findNtFileHdr(BYTE* loadedData, size_t loadedSize);
	BYTE* findSecByPatterns(MemPageData &memPage);
	IMAGE_SECTION_HEADER* findSectionsHdr(MemPageData &memPageData);

	HANDLE processHandle;
	MemPageData &memPage;
	MemPageData *prevMemPage;
};
