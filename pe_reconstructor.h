#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "scanners/artefact_scanner.h"

class PeReconstructor {
public:
	PeReconstructor(ArtefactScanReport* _report)
		: report(_report),
		vBuf(nullptr), vBufSize(0), unmap(true)
	{
	}

	~PeReconstructor() {
		freeBuffer();
	}

	bool reconstruct(HANDLE processHandle);

	bool dumpToFile(std::string dumpFileName, IN OPTIONAL peconv::ExportsMapper* exportsMap = nullptr);

protected:
	void freeBuffer() {
		peconv::free_aligned(vBuf);
		vBuf = nullptr;
		vBufSize = 0;
	}

	bool reconstructPeHdr();
	bool reconstructSectionsHdr(HANDLE processHandle);

	ArtefactScanReport* report;
	BYTE *vBuf;
	size_t vBufSize;

	bool unmap;
};
