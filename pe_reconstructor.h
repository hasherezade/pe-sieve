#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <map>

#include "peconv.h"
#include "scanners/artefact_scanner.h"

class PeReconstructor {
public:
	PeReconstructor(PeArtefacts _artefacts)
		: artefacts(_artefacts),
		vBuf(nullptr), vBufSize(0), moduleBase(0), dumpMode(peconv::PE_DUMP_AUTO)
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
		moduleBase = 0;
	}

	bool reconstructPeHdr();
	bool reconstructSectionsHdr(HANDLE processHandle);

	PeArtefacts artefacts;
	BYTE *vBuf;
	size_t vBufSize;
	ULONGLONG moduleBase;

	peconv::t_pe_dump_mode dumpMode;
};
