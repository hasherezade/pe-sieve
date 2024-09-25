#pragma once
#include <windows.h>
#include <vector>
#include <fstream>

#include "module_scanner.h"
#include "pe_section.h"
#include "patch_list.h"

namespace pesieve {

	//!  A report from the code scan, generated by CodeScanner
	class CodeScanReport : public ModuleScanReport
	{
	public:
		typedef enum section_status {
			SECTION_SCAN_ERR = -1,
			SECTION_NOT_MODIFIED = 0,
			SECTION_PATCHED = 1,
			SECTION_UNPACKED = 2
		} t_section_status;

		CodeScanReport(HMODULE _module, size_t _moduleSize)
			: ModuleScanReport(_module, _moduleSize)
		{
		}

		size_t countSectionsWithStatus(const t_section_status neededStatus)
		{
			size_t counter = 0;
			std::map<DWORD, t_section_status>::iterator itr;
			for (itr = sectionToResult.begin(); itr != sectionToResult.end(); ++itr) {
				const t_section_status status = itr->second;
				if (status == neededStatus) {
					counter++;
				}
			}
			return counter;
		}

		const virtual void fieldsToJSON(std::stringstream &outs, size_t level, const pesieve::t_json_level &jdetails)
		{
			const size_t inaccessibleCount = countInaccessibleSections();
			const size_t scannedCount = sectionToResult.size() - inaccessibleCount;
			ModuleScanReport::_toJSON(outs, level);
			if (sectionToResult.size() > 0) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"scanned_sections\" : ");
				outs << std::dec << scannedCount;
			}
			if (inaccessibleCount > 0) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"inaccessible_sections\" : ");
				outs << std::dec << inaccessibleCount;
			}
			const size_t unpacked = countUnpackedSections();
			if (unpacked > 0) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"unpacked_sections\" : ");
				outs << std::dec << unpacked;
			}
			if (patchesList.size() > 0) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"patches\" : ");
				outs << std::dec << patchesList.size();

				if (jdetails >= JSON_DETAILS) {
					outs << ",\n";
					const bool is_short = (jdetails < JSON_DETAILS2) ? true : false;
					patchesList.toJSON(outs, level, is_short);
				}
			}
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level, const pesieve::t_json_level &jdetails)
		{
			OUT_PADDED(outs, level, "\"code_scan\" : {\n");
			fieldsToJSON(outs, level + 1, jdetails);
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
			return countSectionsWithStatus(SECTION_UNPACKED);
		}

		size_t countInaccessibleSections()
		{
			return countSectionsWithStatus(SECTION_SCAN_ERR);
		}

		size_t generateTags(const std::string &reportPath);

		std::map<DWORD, t_section_status> sectionToResult;
		PatchList patchesList;
	};


	//!  A scanner for detection of patches in the code.
	class CodeScanner : public ModuleScanner {
	public:

		CodeScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData)
			: ModuleScanner(hProc, moduleData, remoteModData),
			isScanData(false), isScanInaccessible(false)
		{
		}

		virtual CodeScanReport* scanRemote();

		void setScanData(bool enable) { this->isScanData = enable; }
		void setScanInaccessible(bool enable) { this->isScanInaccessible = enable; }

	private:

		size_t collectExecutableSections(RemoteModuleData &remoteModData, std::map<size_t, PeSection*> &sections, CodeScanReport &my_report);

		void freeExecutableSections(std::map<size_t, PeSection*> &sections);

		bool postProcessScan(IN OUT CodeScanReport &report);

		t_scan_status scanUsingBase(IN ULONGLONG load_base, IN std::map<size_t, PeSection*> &remote_code, OUT std::map<DWORD, CodeScanReport::t_section_status> &sectionToResult, OUT PatchList &patchesList);

		CodeScanReport::t_section_status scanSection(PeSection &originalSec, PeSection &remoteSec, OUT PatchList &patchesList);

		bool clearIAT(PeSection &originalSec, PeSection &remoteSec);

		bool clearExports(PeSection &originalSec, PeSection &remoteSec);

		bool clearLoadConfig(PeSection &originalSec, PeSection &remoteSec);

		size_t collectPatches(DWORD section_rva, PBYTE orig_code, PBYTE patched_code, size_t code_size, OUT PatchList &patchesList);

		bool isScanData;
		bool isScanInaccessible;
	};

}; //namespace pesieve

