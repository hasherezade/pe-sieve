#include "iat_scanner.h"

#include <peconv.h>

#include <fstream>

class ImportInfoCallback : public peconv::ImportThunksCallback
{
public:
	ImportInfoCallback(BYTE* _modulePtr, size_t _moduleSize, std::map<ULONGLONG, peconv::ExportedFunc> &_storedFunc)
		: ImportThunksCallback(_modulePtr, _moduleSize), storedFunc(_storedFunc)
	{
	}

	virtual bool processThunks(LPSTR lib_name, ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr)
	{
		if (this->is64b) {
			IMAGE_THUNK_DATA64* desc = reinterpret_cast<IMAGE_THUNK_DATA64*>(origFirstThunkPtr);
			ULONGLONG* call_via = reinterpret_cast<ULONGLONG*>(firstThunkPtr);
			return processThunks_tpl<ULONGLONG, IMAGE_THUNK_DATA64>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG64);
		}
		IMAGE_THUNK_DATA32* desc = reinterpret_cast<IMAGE_THUNK_DATA32*>(origFirstThunkPtr);
		DWORD* call_via = reinterpret_cast<DWORD*>(firstThunkPtr);
		return processThunks_tpl<DWORD, IMAGE_THUNK_DATA32>(lib_name, desc, call_via, IMAGE_ORDINAL_FLAG32);
	}

protected:
	template <typename T_FIELD, typename T_IMAGE_THUNK_DATA>
	bool processThunks_tpl(LPSTR lib_name, T_IMAGE_THUNK_DATA* desc, T_FIELD* call_via, T_FIELD ordinal_flag)
	{
		ULONGLONG call_via_rva = ((ULONG_PTR)call_via - (ULONG_PTR)this->modulePtr);
		T_FIELD raw_ordinal = 0;
		bool is_by_ord = (desc->u1.Ordinal & ordinal_flag) != 0;
		if (is_by_ord) {
			raw_ordinal = desc->u1.Ordinal & (~ordinal_flag);
#ifdef _DEBUG
			std::cout << "raw ordinal: " << std::hex << raw_ordinal << std::endl;
#endif
			this->storedFunc[call_via_rva] = peconv::ExportedFunc(peconv::get_dll_shortname(lib_name), raw_ordinal);
		}
		else {
			PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)((ULONGLONG)modulePtr + desc->u1.AddressOfData);
			LPSTR func_name = reinterpret_cast<LPSTR>(by_name->Name);
			raw_ordinal = by_name->Hint;
			this->storedFunc[call_via_rva] = peconv::ExportedFunc(peconv::get_dll_shortname(lib_name), func_name, raw_ordinal);
		}
		return true;
	}

	//fields:
	std::map<ULONGLONG, peconv::ExportedFunc> &storedFunc;
};
///----

bool IATScanReport::saveNotRecovered(IN std::string fileName,
	IN HANDLE hProcess,
	IN const std::map<ULONGLONG, peconv::ExportedFunc> *storedFunc,
	IN peconv::ImpsNotCovered &notCovered,
	IN const ProcessModules &modulesInfo,
	IN const peconv::ExportsMapper *exportsMap)
{
	const char delim = ';';

	if (notCovered.count() == 0) {
		return false;
	}
	std::ofstream report;
	report.open(fileName);
	if (report.is_open() == false) {
		return false;
	}

	std::map<ULONGLONG,ULONGLONG>::iterator itr;
	for (itr = notCovered.thunkToAddr.begin(); itr != notCovered.thunkToAddr.end(); itr++)
	{
		const ULONGLONG thunk = itr->first;
		const ULONGLONG addr = itr->second;
		report << std::hex << thunk;

		if (storedFunc) {
			report << delim;
			std::map<ULONGLONG, peconv::ExportedFunc>::const_iterator found = storedFunc->find(thunk);
			if (found != storedFunc->end()) {
				const peconv::ExportedFunc &func = found->second;
				report << func.toString() << "->";
			}
			else {
				report << "(unknown)" << "->";
			}
		}

		if (exportsMap) {
			report << delim;
			LoadedModule *modExp = modulesInfo.getModuleContaining(addr);
			ULONGLONG module_start = (modExp) ? modExp->start : peconv::fetch_alloc_base(hProcess, (BYTE*)addr);

			const peconv::ExportedFunc* func = exportsMap->find_export_by_va(addr);
			if (!func) {
				char moduleName[MAX_PATH] = { 0 };
				if (GetModuleBaseNameA(hProcess, (HMODULE)module_start, moduleName, sizeof(moduleName))) {
					report << peconv::get_dll_shortname(moduleName) << ".(unknown_func)";
				}
				else {
					report << "(unknown)";
				}
			}
			else {
				report << func->toString();
			}

			size_t offset = addr - module_start;
			report << delim << std::hex << module_start << "+" << offset;

			if (modExp) {
				report << delim << modExp->isSuspicious();
			}
		}
		report << std::endl;
	}
	report.close();
	return true;
}

bool IATScanReport::generateList(IN const std::string &fileName, IN HANDLE hProcess, IN const ProcessModules &modulesInfo, IN const peconv::ExportsMapper *exportsMap)
{
	return saveNotRecovered(fileName,
		hProcess,
		&storedFunc,
		notCovered,
		modulesInfo,
		exportsMap);
}

IATScanReport* IATScanner::scanRemote()
{
	if (!remoteModData.isInitialized() || !remoteModData.isFullImageLoaded()) {
		std::cerr << "[-] Failed to initialize remote module" << std::endl;
		return nullptr;
	}
	BYTE *vBuf = remoteModData.imgBuffer;
	size_t vBufSize = remoteModData.imgBufferSize;
	if (!vBuf) {
		return nullptr;
	}
	peconv::ImpsNotCovered not_covered;
	peconv::fix_imports(vBuf, vBufSize, exportsMap, &not_covered);

	t_scan_status status = SCAN_NOT_SUSPICIOUS;
	if (not_covered.count() > 0) {
		status = SCAN_SUSPICIOUS;
	}

	IATScanReport *report = new IATScanReport(processHandle, remoteModData.modBaseAddr, remoteModData.getModuleSize(), moduleData.szModName);
	if (!report) {
		return nullptr;
	}

	if (not_covered.count()) {
		listAllImports(report->storedFunc);
	}

	report->status = status;
	report->hookedCount = not_covered.count();
	report->notCovered = not_covered;
	return report;
}

void IATScanner::listAllImports(std::map<ULONGLONG, peconv::ExportedFunc> &_storedFunc)
{
	BYTE *vBuf = remoteModData.imgBuffer; 
	size_t vBufSize = remoteModData.imgBufferSize;
	if (!vBuf) {
		return;
	}
	ImportInfoCallback callback(vBuf, vBufSize, _storedFunc);
	peconv::process_import_table(vBuf, vBufSize, &callback);
}
