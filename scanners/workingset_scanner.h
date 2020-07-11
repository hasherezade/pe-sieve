#pragma once

#include <windows.h>
#include <psapi.h>
#include <map>

#include <peconv.h>
#include "module_scan_report.h"
#include "mempage_data.h"
#include "scan_report.h"

#include "../utils/format_util.h"

namespace pesieve {

	class WorkingSetScanReport : public ModuleScanReport
	{
	public:
		WorkingSetScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize, t_scan_status status)
			: ModuleScanReport(processHandle, _module, _moduleSize, status)
		{
			is_executable = false;
			is_listed_module = false;
			protection = 0;
			has_pe = false; //not a PE file
			has_shellcode = true;
			mapping_type = 0;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
		{
			OUT_PADDED(outs, level, "\"workingset_scan\" : {\n");
			fieldsToJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}

		const virtual void fieldsToJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
		{
			ModuleScanReport::toJSON(outs, level);
			outs << ",\n";
			OUT_PADDED(outs, level, "\"has_pe\" : ");
			outs << std::dec << has_pe;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"has_shellcode\" : ");
			outs << std::dec << has_shellcode;
			if (!is_executable) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"is_executable\" : ");
				outs << std::dec << is_executable;
			}
			outs << ",\n";
			OUT_PADDED(outs, level, "\"is_listed_module\" : ");
			outs << std::dec << is_listed_module;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"protection\" : ");
			outs << "\"" << std::hex << protection << "\"";
			outs << ",\n";
			OUT_PADDED(outs, level, "\"mapping_type\" : ");
			outs << "\"" << translate_mapping_type(mapping_type) << "\"";
			if (mapping_type == MEM_IMAGE || mapping_type == MEM_MAPPED) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"mapped_name\" : ");
				outs << "\"" << pesieve::util::escape_path_separators(mapped_name) << "\"";
			}
		}

		bool is_executable;
		bool is_listed_module;
		bool has_pe;
		bool has_shellcode;
		DWORD protection;
		DWORD mapping_type;
		std::string mapped_name; //if the region is mapped from a file

	protected:
		static std::string translate_mapping_type(DWORD type)
		{
			switch (type) {
			case MEM_PRIVATE: return "MEM_PRIVATE";
			case MEM_MAPPED: return "MEM_MAPPED";
			case MEM_IMAGE: return "MEM_IMAGE";
			}
			return "unknown";
		}
	};

	class WorkingSetScanner {
	public:
		WorkingSetScanner(HANDLE _procHndl, MemPageData &_memPageDatal, pesieve::t_params _args, ProcessScanReport& _process_report)
			: processHandle(_procHndl), memPage(_memPageDatal),
			args(_args),
			processReport(_process_report)
		{
		}

		virtual ~WorkingSetScanner() {}

		virtual WorkingSetScanReport* scanRemote();

	protected:
		bool scanImg();
		bool isScannedAsModule(MemPageData &memPageData);

		bool isExecutable(MemPageData &memPageData);
		bool isPotentiallyExecutable(MemPageData &memPageData, const t_data_scan_mode &mode);
		bool isCode(MemPageData &memPageData);
		WorkingSetScanReport* scanExecutableArea(MemPageData &memPageData);

		HANDLE processHandle;
		MemPageData &memPage;

		ProcessScanReport& processReport;
		pesieve::t_params args;
	};

}; //namespace pesieve
