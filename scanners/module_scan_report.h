#pragma once

#include <windows.h>

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <peconv.h>
#include "pe_sieve_types.h"

#include "../utils/path_util.h"
#include "../utils/format_util.h"

namespace pesieve {

	typedef enum module_scan_status {
		SCAN_ERROR = -1,
		SCAN_NOT_SUSPICIOUS = 0,
		SCAN_SUSPICIOUS = 1
	} t_scan_status;

	//!  A base class of all the reports detailing on the output of the performed module's scan.
	class ModuleScanReport
	{
	public:
		static const size_t JSON_LEVEL = 1;

		static t_scan_status get_scan_status(const ModuleScanReport *report)
		{
			if (report == nullptr) {
				return SCAN_ERROR;
			}
			return report->status;
		}

		ModuleScanReport(HMODULE _module, size_t _moduleSize, t_scan_status _status)
		{
			this->module = _module;
			this->moduleSize = _moduleSize;
			this->status = _status;
			this->isDotNetModule = false;
		}

		ModuleScanReport(HMODULE _module, size_t _moduleSize)
		{
			this->module = _module;
			this->moduleSize = _moduleSize;
			this->isDotNetModule = false;
			this->status = SCAN_NOT_SUSPICIOUS;
		}

		virtual ~ModuleScanReport() {}

		virtual ULONGLONG getRelocBase()
		{
			return (ULONGLONG)this->module;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC) = 0;

		HMODULE module;
		size_t moduleSize;
		bool isDotNetModule;
		std::string moduleFile;
		t_scan_status status;

	protected:
		const virtual bool _toJSON(std::stringstream& outs, size_t level = JSON_LEVEL, const pesieve::t_json_level& jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"module\" : ");
			outs << "\"" << std::hex << (ULONGLONG)module << "\"" << ",\n";
			if (moduleSize){
				OUT_PADDED(outs, level, "\"module_size\" : ");
				outs << "\"" << std::hex << (ULONGLONG)moduleSize << "\"" << ",\n";
			}
			if (moduleFile.length()) {
				OUT_PADDED(outs, level, "\"module_file\" : ");
				outs << "\"" << pesieve::util::escape_path_separators(moduleFile) << "\"" << ",\n";
			}
			OUT_PADDED(outs, level, "\"status\" : ");
			outs << std::dec << status;
			if (isDotNetModule) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"is_dot_net\" : \"");
				outs << isDotNetModule << "\"";
			}
			return true;
		}

	};

	class UnreachableModuleReport : public ModuleScanReport
	{
	public:
		UnreachableModuleReport(HMODULE _module, size_t _moduleSize, std::string _moduleFile)
			: ModuleScanReport(_module, _moduleSize, SCAN_ERROR)
		{
			moduleFile = _moduleFile;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"unreachable_scan\" : ");
			outs << "{\n";
			ModuleScanReport::_toJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}
	};

	class SkippedModuleReport : public ModuleScanReport
	{
	public:
		SkippedModuleReport(HMODULE _module, size_t _moduleSize, std::string _moduleFile)
			: ModuleScanReport(_module, _moduleSize, SCAN_NOT_SUSPICIOUS)
		{
			moduleFile = _moduleFile;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"skipped_scan\" : ");
			outs << "{\n";
			ModuleScanReport::_toJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}
	};

	class MalformedHeaderReport : public ModuleScanReport
	{
	public:
		MalformedHeaderReport(HMODULE _module, size_t _moduleSize, std::string _moduleFile)
			: ModuleScanReport(_module, _moduleSize, SCAN_SUSPICIOUS)
		{
			moduleFile = _moduleFile;
		}

		const virtual bool toJSON(std::stringstream &outs, size_t level = JSON_LEVEL, const pesieve::t_json_level &jdetails = JSON_BASIC)
		{
			OUT_PADDED(outs, level, "\"malformed_header\" : ");
			outs << "{\n";
			ModuleScanReport::_toJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}
	};

}; //namespace pesieve
