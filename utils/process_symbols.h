#pragma once

#include <string>
#include <iostream>

#include <dbghelp.h>
#include "dbg_help_wrapper.h"

//---
class ProcessSymbolsManager
{
public:

	ProcessSymbolsManager()
		: hProcess(NULL), isInit(false)
	{
	}

	~ProcessSymbolsManager()
	{
		FreeSymbols();
	}

	ProcessSymbolsManager(const ProcessSymbolsManager&) = delete;

	ProcessSymbolsManager& operator=(const ProcessSymbolsManager&) = delete;

	//---
#ifdef _TEST
	void ForceRealSymbolDownload(HANDLE hProcess)
	{
		HMODULE ntdll_hndl = GetModuleHandleA("ntdll.dll");
		std::cout << "\n[+] Try export first...\n";
		dumpSymbolInfo((DWORD64)GetProcAddress(ntdll_hndl, "NtLoadKeyEx"));
		std::cout << "\n[+] Forcing SymFromAddr on non-export address...\n";
		dumpSymbolInfo((DWORD64)GetModuleHandleA("kernel32.dll") + 0x20000);
		dumpSymbolInfo((DWORD64)ntdll_hndl + 0x7A80);

	}
#endif //_TEST
	//---

	static DWORD BuildSymOptions()
	{
		DWORD symOptions =
			SYMOPT_CASE_INSENSITIVE |
			SYMOPT_UNDNAME |
			SYMOPT_FAIL_CRITICAL_ERRORS |
			SYMOPT_AUTO_PUBLICS |
			SYMOPT_INCLUDE_32BIT_MODULES |
			SYMOPT_NO_PROMPTS;
//#ifdef _DEBUG
		symOptions |= SYMOPT_DEBUG;
//#endif
		return symOptions;
	}

	static std::string FilterSymbolPath(const std::string& input, bool allowDownload)
	{
		std::string result;

		size_t start = 0;

		while (start < input.size()) {
			size_t end =
				input.find(';', start);

			if (end == std::string::npos) {
				end = input.size();
			}

			std::string token = input.substr(start, end - start);
			token.erase(0, token.find_first_not_of(" \t"));

			size_t last = token.find_last_not_of(" \t");
			if (last != std::string::npos) {
				token.erase(last + 1);
			}
			else {
				token.clear();
			}

			if (token.empty()) {
				start = end + 1;
				continue;
			}

			const bool isSrv = (_strnicmp(token.c_str(), "srv*", 4) == 0);
			if (isSrv) {
				if (allowDownload) {
					if (!result.empty()) {
						result += ";";
					}
					result += token;
				}
				else {
					size_t first = token.find('*');
					size_t second = token.find('*', first + 1);

					if (first != std::string::npos &&
						second != std::string::npos &&
						second > first + 1)
					{
						std::string cache =
							token.substr(
								first + 1,
								second - first - 1);

						if (!cache.empty()) {
							if (!result.empty()) {
								result += ";";
							}
							result += cache;
						}
					}
				}
			}
			else {
				if (!result.empty()) {
					result += ";";
				}
				result += token;
			}
			start = end + 1;
		}
		return result;
	}

	static std::string BuildSymbolPath(bool enableAutoDownload)
	{
		const DWORD bufferSize = 4096;
		char envBuffer[bufferSize] = { 0 };
		std::string path;

		if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", envBuffer, bufferSize)) {
			path += FilterSymbolPath(envBuffer, enableAutoDownload);
		}

		if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", envBuffer, bufferSize)) {
			const std::string filtered = FilterSymbolPath(envBuffer, enableAutoDownload);
			if (!filtered.empty()) {
				if (!path.empty()) {
					path += ";";
				}
				path += filtered;
			}
		}
		return path;
	}

	bool InitSymbols(HANDLE process, bool enableAutoDownload, bool lazy)
	{
		if (!process || process == INVALID_HANDLE_VALUE) {
			return false;
		}

		if (isInit) {
			return true;
		}

		DWORD options = BuildSymOptions();

		if (enableAutoDownload) {
			options &= ~SYMOPT_DISABLE_SYMSRV_AUTODETECT;
		}
		else {
			options |= SYMOPT_DISABLE_SYMSRV_AUTODETECT;
		}

		if (lazy) {
			options |= SYMOPT_DEFERRED_LOADS;
		}
		else {
			options &= ~SYMOPT_DEFERRED_LOADS;
		}

		const std::string path = BuildSymbolPath(enableAutoDownload);

		if (!DbgHelpWrapper::InitializeProcess(process, path, options)) {
			return false;
		}

		DbgHelpWrapper::RefreshModuleList(process);

		hProcess = process;
		isInit = true;
#ifdef _TEST
		ForceRealSymbolDownload(process);
#endif
		return true;
	}

	bool RefreshModules()
	{
		if (!isInit) {
			return false;
		}
		return DbgHelpWrapper::RefreshModuleList(hProcess);
	}

	bool RunStackWalk(
		_In_ DWORD MachineType,
		_In_ HANDLE hThread,
		_Inout_ LPSTACKFRAME StackFrame,
		_Inout_ PVOID ContextRecord,
		_In_opt_ PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
		_In_opt_ PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
		_In_opt_ PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
		_In_opt_ PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress
	)
	{
		if (!isInit) {
			return false;
		}
		return DbgHelpWrapper::RunStackWalk(MachineType,
			this->hProcess,
			hThread,
			StackFrame,
			ContextRecord,
			ReadMemoryRoutine,
			FunctionTableAccessRoutine,
			GetModuleBaseRoutine,
			TranslateAddress);
	}

	bool IsInitialized() const
	{
		return isInit;
	}

	void NormalizeNtZwPrefix(std::string& funcName)
	{
		if (funcName.size() < 2) {
			return;
		}

		if (funcName[0] == 'Z' && funcName[1] == 'w') {
			funcName[0] = 'N';
			funcName[1] = 't';
		}
	}

	std::string funcNameFromAddr(ULONG_PTR addr, size_t* displacement = NULL)
	{
		if (!isInit) {
			return "";
		}

		__declspec(align(8)) char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };

		PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol->MaxNameLen =MAX_SYM_NAME;

		DWORD64 disp = 0;

		if (!DbgHelpWrapper::FromAddress(hProcess, static_cast<DWORD64>(addr),symbol, &disp)) {
			return "";
		}

		if (displacement) {
			*displacement = static_cast<size_t>(disp);
		}

		std::string funcName(symbol->Name);

		NormalizeNtZwPrefix(funcName);
		return funcName;
	}

	bool dumpSymbolInfo(ULONG_PTR va)
	{
		if (!isInit) {
			return false;
		}

		__declspec(align(8)) char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME ] = { 0 };

		PSYMBOL_INFO symbol = reinterpret_cast<PSYMBOL_INFO>(buffer);
		symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol->MaxNameLen = MAX_SYM_NAME;

		DWORD64 displacement = 0;

		BOOL result = DbgHelpWrapper::FromAddress(hProcess, static_cast<DWORD64>(va), symbol, &displacement);
		std::cout << std::dec << "[" << GetProcessId(hProcess) << "] " << std::hex << va;

		if (result) {
			std::cout << " Base: " << symbol->ModBase << " : " << symbol->Name
					<< " +0x" << displacement << " Flags: " << symbol->Flags << " Tag: " << symbol->Tag << std::endl;
		}
		else {
			std::cout << " UNK" << std::endl;
		}
		return result == TRUE;
	}

protected:

	bool FreeSymbols()
	{
		if (!isInit) {
			return true;
		}
		if (!DbgHelpWrapper::CleanupProcess(hProcess)) {
			return false;
		}
		isInit = false;
		hProcess = NULL;
		return true;
	}

protected:

	HANDLE hProcess;
	bool isInit;
};
