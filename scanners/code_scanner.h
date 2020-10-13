#pragma once
#include <windows.h>
#include <vector>
#include <fstream>

#include "module_scanner.h"
#include "pe_section.h"
#include "patch_list.h"

namespace pesieve {

	class CodeScanReport : public ModuleScanReport
	{
	public:
		
		typedef enum section_status {
			SECTION_SCAN_ERR = -1,
			SECTION_NOT_MODIFIED = 0,
			SECTION_PATCHED = 1,
			SECTION_UNPACKED = 2
		} t_section_status;

		CodeScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
			: ModuleScanReport(processHandle, _module, _moduleSize), relocBase(0)
		{
		}

		const virtual void fieldsToJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
		{
			ModuleScanReport::toJSON(outs, level);
			if (patchesList.size() > 0) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"patches\" : ");
				outs << std::dec << patchesList.size();
			}
			if (sectionToResult.size() > 0) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"scanned_sections\" : ");
				outs << std::dec << sectionToResult.size();
			}
			const size_t unpacked = countUnpackedSections();
			if (unpacked > 0) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"unpacked_sections\" : ");
				outs << std::dec << unpacked;
			}
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
		{
			OUT_PADDED(outs, level, "\"code_scan\" : {\n");
			fieldsToJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}

		virtual ULONGLONG getRelocBase()
		{
			return this->relocBase;
		}

		size_t countUnpackedSections()
		{
			size_t counter = 0;
			std::map<DWORD, t_section_status>::iterator itr;
			for (itr = sectionToResult.begin(); itr != sectionToResult.end(); itr++) {
				const t_section_status status = itr->second;
				if (status == SECTION_UNPACKED) {
					counter++;
				}
			}
			return counter;
		}

		size_t generateTags(std::string reportPath);

		ULONGLONG relocBase;
		std::map<DWORD, t_section_status> sectionToResult;
		PatchList patchesList;
	};

	class CodeScanner : public ModuleScanner {
	public:

		CodeScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData)
			: ModuleScanner(hProc, moduleData, remoteModData),
			isScanData(false) { }

		virtual CodeScanReport* scanRemote();

		void scanData(bool enable) { this->isScanData = enable; }

	private:

		size_t collectExecutableSections(RemoteModuleData &remoteModData, std::map<size_t, PeSection*> &sections);

		void freeExecutableSections(std::map<size_t, PeSection*> &sections);

		bool postProcessScan(IN OUT CodeScanReport &report);

		t_scan_status scanUsingBase(IN ULONGLONG load_base, IN std::map<size_t, PeSection*> &remote_code, OUT std::map<DWORD, CodeScanReport::t_section_status> &sectionToResult, OUT PatchList &patchesList);

		CodeScanReport::t_section_status scanSection(PeSection &originalSec, PeSection &remoteSec, OUT PatchList &patchesList);

		bool clearIAT(PeSection &originalSec, PeSection &remoteSec);

		bool clearExports(PeSection &originalSec, PeSection &remoteSec);

		bool clearLoadConfig(PeSection &originalSec, PeSection &remoteSec);

		size_t collectPatches(DWORD section_rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, OUT PatchList &patchesList);

		bool isScanData;
	};

}; //namespace pesieve

