#pragma once

#include <windows.h>

#include "module_scanner.h"

namespace pesieve {

	class HeadersScanReport : public ModuleScanReport
	{
	public:
		HeadersScanReport(HANDLE processHandle, HMODULE _module, size_t _moduleSize)
			: ModuleScanReport(processHandle, _module, _moduleSize),
			dosHdrModified(false), fileHdrModified(false), ntHdrModified(false),
			secHdrModified(false),
			epModified(false), archMismatch(false), is64(false)
		{
		}

		const virtual void fieldsToJSON(std::stringstream &outs, size_t level = JSON_LEVEL)
		{
			bool is_replaced = isHdrReplaced();
			ModuleScanReport::toJSON(outs, level);
			outs << ",\n";
			OUT_PADDED(outs, level, "\"is_pe_replaced\" : ");
			outs << is_replaced;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"dos_hdr_modified\" : ");
			outs << dosHdrModified;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"file_hdr_modified\" : ");
			outs << fileHdrModified;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"nt_hdr_modified\" : ");
			outs << ntHdrModified;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"ep_modified\" : ");
			outs << epModified;
			outs << ",\n";
			OUT_PADDED(outs, level, "\"sec_hdr_modified\" : ");
			outs << secHdrModified;

			if (archMismatch) {
				outs << ",\n";
				OUT_PADDED(outs, level, "\"arch_mismatch\" : ");
				outs << archMismatch;
				outs << ",\n";
				OUT_PADDED(outs, level, "\"is64b\" : ");
				outs << is64;
			}
		}

		const virtual bool toJSON(std::stringstream& outs, size_t level = JSON_LEVEL)
		{
			OUT_PADDED(outs, level, "\"headers_scan\" : {\n");
			fieldsToJSON(outs, level + 1);
			outs << "\n";
			OUT_PADDED(outs, level, "}");
			return true;
		}

		bool isHdrReplaced()
		{
			return secHdrModified;
		}

		bool epModified;
		bool dosHdrModified;
		bool fileHdrModified;
		bool ntHdrModified;
		bool secHdrModified;
		bool archMismatch; // the loaded module is of different architecture than the module read from the corresponding path
		DWORD is64; // is the remote module 64bit
	};

	class HeadersScanner : public ModuleScanner {
	public:
		HeadersScanner(HANDLE hProc, ModuleData &moduleData, RemoteModuleData &remoteModData)
			: ModuleScanner(hProc, moduleData, remoteModData)
		{
		}

		virtual HeadersScanReport* scanRemote();

	private:
		bool zeroUnusedFields(PBYTE hdr_buffer, size_t hdrs_size);
		bool isSecHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size);
		bool isDosHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size);
		bool isFileHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size);
		bool isNtHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size);
	};

}; //namespace pesieve

