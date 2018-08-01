#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "mempage_scanner.h"

class ArtefactScanReport : public MemPageScanReport
{
public:
	ArtefactScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, t_scan_status status)
		: MemPageScanReport(processHandle, _module, _moduleSize, status)
	{
		 is_executable = true;
		 is_manually_loaded = true;
		 protection = 0;
		 is_shellcode = true;
		 sections_hdrs = 0;
	}

	const virtual bool toJSON(std::stringstream &outs)
	{
		outs << "\"artefacts_scan\" : ";
		outs << "{\n";
		MemPageScanReport::fieldsToJSON(outs);

		outs << ",\n";
		outs << "\"sections_hdrs\" : ";
		outs << "\"" << std::hex << sections_hdrs << "\"";
		outs << ",\n";
		outs << "\"sections_count\" : ";
		outs << std::hex << sections_count;
		
		outs << "\n}";
		return true;
	}

	ULONGLONG sections_hdrs;
	size_t sections_count;
};


class ArtefactScanner {
public:
	ArtefactScanner(HANDLE _procHndl, MemPageData &_memPageData)
		: processHandle(_procHndl), memPage(_memPageData)
	{
	}
	virtual ~ArtefactScanner() {}

	virtual ArtefactScanReport* scanRemote();
protected:
	IMAGE_SECTION_HEADER* findSectionsHdr(MemPageData &memPageData);

	HANDLE processHandle;
	MemPageData &memPage;
};
