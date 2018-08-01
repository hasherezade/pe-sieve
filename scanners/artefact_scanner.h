#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "module_scan_report.h"
#include "mempage_scanner.h"

class ArtefactScanner {
public:
	ArtefactScanner(HANDLE _procHndl, MemPageData &_memPageData)
		: processHandle(_procHndl), memPage(_memPageData)
	{
	}
	virtual ~ArtefactScanner() {}

	virtual MemPageScanReport* scanRemote();
protected:
	IMAGE_SECTION_HEADER* findSectionsHdr(MemPageData &memPageData);

	HANDLE processHandle;
	MemPageData &memPage;
};
