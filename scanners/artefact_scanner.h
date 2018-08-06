#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "mempage_scanner.h"

#define INVALID_OFFSET (-1)
#define PE_NOT_FOUND 0

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
		isMzPeFound = false;
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

	const virtual bool fieldsToJSON(std::stringstream &outs)
	{
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
	
	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"artefacts\" : ";
		outs << "{\n";
		fieldsToJSON(outs);
		outs << "\n}";
		return true;
	}

	LONGLONG regionStart;
	size_t peBaseOffset; //offset from the regionStart (PE may not start at the first page of the region)
	size_t ntFileHdrsOffset; //offset from the regionStart
	size_t secHdrsOffset; //offset from the regionStart
	size_t secCount;
	size_t calculatedImgSize;
	bool isMzPeFound;
};

class ArtefactScanReport : public MemPageScanReport
{
public:
	ArtefactScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, t_scan_status status, PeArtefacts &peArt)
		: MemPageScanReport(processHandle, _module, _moduleSize, status),
		artefacts(peArt), 
		initialRegionSize(_moduleSize)
	{
		is_executable = true;
		is_manually_loaded = true;
		protection = 0;
		is_shellcode = isShellcode(peArt);

		size_t total_region_size = peArt.calculatedImgSize + peArt.peBaseOffset;
		if (total_region_size > this->moduleSize) {
			this->moduleSize = total_region_size;
		}
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"artefacts_scan\" : ";
		outs << "{\n";
		MemPageScanReport::fieldsToJSON(outs);
		outs << ",\n";
		artefacts.toJSON(outs);
		outs << "\n}";
		return true;
	}

	PeArtefacts artefacts;
	size_t initialRegionSize;

protected:
	bool isShellcode(PeArtefacts &peArt)
	{
		bool is_shellcode = false;
		if (peArt.peBaseOffset > 0) {
			// the total region is bigger than the PE
			is_shellcode = true;
		}
		size_t pe_region_size = peArt.calculatedImgSize + peArt.peBaseOffset;
		if (pe_region_size < this->initialRegionSize) {
			// the total region is bigger than the PE
			is_shellcode = true;
		}
		return is_shellcode;
	}
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
	class ArtefactsMapping
	{
	public:
		ArtefactsMapping(MemPageData &_memPage) :
			memPage(_memPage)
		{
			pe_image_base = PE_NOT_FOUND;
			nt_file_hdr = nullptr;
			sec_hdr = nullptr;
			isMzPeFound = false;
		}

		bool foundAny()
		{
			if (sec_hdr || nt_file_hdr) {
				return true;
			}
			return false;
		}

		MemPageData &memPage;
		ULONGLONG pe_image_base;
		IMAGE_FILE_HEADER* nt_file_hdr;
		IMAGE_SECTION_HEADER* sec_hdr;
		bool isMzPeFound;
	};

	void deletePrevPage()
	{
		if (this->prevMemPage) {
			delete this->prevMemPage;
		}
		this->prevMemPage = nullptr;
	}


	bool findMzPe(ArtefactsMapping &mapping);
	bool setMzPe(ArtefactsMapping &mapping, IMAGE_DOS_HEADER* _dos_hdr);
	bool setSecHdr(ArtefactsMapping &mapping, IMAGE_SECTION_HEADER* _sec_hdr);
	bool setNtFileHdr(ArtefactScanner::ArtefactsMapping &aMap, IMAGE_FILE_HEADER* _nt_hdr);
	PeArtefacts *generateArtefacts(ArtefactsMapping &aMap);

	PeArtefacts* findArtefacts(MemPageData &memPage);
	PeArtefacts* findInPrevPages(ULONGLONG addr_start, ULONGLONG addr_stop);

	ULONGLONG calcPeBase(MemPageData &memPage, BYTE *hdr_ptr);
	size_t calcImageSize(MemPageData &memPage, IMAGE_SECTION_HEADER *hdr_ptr, ULONGLONG pe_image_base);

	IMAGE_FILE_HEADER* findNtFileHdr(BYTE* loadedData, size_t loadedSize);
	BYTE* findSecByPatterns(MemPageData &memPage);
	IMAGE_SECTION_HEADER* findSectionsHdr(MemPageData &memPageData);
	IMAGE_DOS_HEADER* findMzPeHeader(MemPageData &memPage);

	HANDLE processHandle;
	MemPageData &memPage;
	MemPageData *prevMemPage;
};
