#pragma once

#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp")


class ProcessSymbolsManager
{
public:

	static DWORD BuildSymOptions()
	{
		DWORD symOptions =
			SYMOPT_CASE_INSENSITIVE |
			SYMOPT_UNDNAME |
			SYMOPT_DEFERRED_LOADS |
			SYMOPT_FAIL_CRITICAL_ERRORS |
			SYMOPT_AUTO_PUBLICS |
			SYMOPT_INCLUDE_32BIT_MODULES |
			SYMOPT_NO_PROMPTS;
#ifdef _DEBUG
		symOptions |= SYMOPT_DEBUG;
#endif
		return symOptions;
	}

	static BOOL InitDbgHelpSession(HANDLE process, const char* searchPath)
	{
		SymSetOptions(BuildSymOptions());

		if (!SymInitialize(process, searchPath, TRUE)) {
			return FALSE;
		}
		return TRUE;
	}

	static std::string FilterSymbolPath(const std::string& input, bool allowDownload)
	{
		std::string result;
		size_t start = 0;

		while (start < input.size())
		{
			size_t end = input.find(';', start);
			if (end == std::string::npos) end = input.size();

			std::string token = input.substr(start, end - start);

			token.erase(0, token.find_first_not_of(" \t"));

			size_t last = token.find_last_not_of(" \t");
			if (last != std::string::npos)
				token.erase(last + 1);
			else
				token.clear();

			if (token.empty()) {
				start = end + 1;
				continue;
			}
			const bool isSrv = (_strnicmp(token.c_str(), "srv*", 4) == 0);

			if (isSrv) {
				if (allowDownload) {
					// Keep full srv* entry
					if (!result.empty()) result += ";";
					result += token;
				}
				else {
					// Extract cache path: srv*<cache>*<server>
					size_t first = token.find('*');
					size_t second = token.find('*', first + 1);

					if (first != std::string::npos && second != std::string::npos && second > first + 1)
					{
						std::string cache = token.substr(first + 1, second - first - 1);

						if (!cache.empty()) {
							if (!result.empty()) result += ";";
							result += cache;
						}
					}
				}
			}
			else {
				// Non-srv entries are always safe
				if (!result.empty()) result += ";";
				result += token;
			}

			start = end + 1;
		}
		return result;
	}

	static std::string BuildSymbolPath(bool enableAutoDownload)
	{
		const size_t bufferSize = 4096;
		char envBuffer[bufferSize] = { 0 };

		std::string path;

		if (GetEnvironmentVariableA("_NT_SYMBOL_PATH", envBuffer, bufferSize)) {
			path += FilterSymbolPath(envBuffer, enableAutoDownload);
		}

		if (GetEnvironmentVariableA("_NT_ALTERNATE_SYMBOL_PATH", envBuffer, bufferSize)) {
			std::string filtered = FilterSymbolPath(envBuffer, enableAutoDownload);

			if (!filtered.empty()) {
				if (!path.empty()) path += ";";
				path += filtered;
			}
		}
		return path;
	}

	static bool InitSymbolsWithPath(HANDLE processHandle, bool enableAutoDownload)
	{
		const size_t bufferSize = MAX_PATH * 4;
		char buffer[bufferSize] = { 0 };
		const std::string fullPathStr = BuildSymbolPath(enableAutoDownload);
		const char* pathPtr = fullPathStr.empty() ? nullptr : fullPathStr.c_str();
		const BOOL isOk = InitDbgHelpSession(processHandle, pathPtr);
#ifdef _DEBUG
		if (isOk) {
			printf("Symbols initialized with path: %s\n", fullPathStr.c_str());
		}
#endif // _DEBUG
		return isOk == TRUE;
	}

//---

	ProcessSymbolsManager()
		: hProcess(NULL), isInit(false)
	{
	}

	~ProcessSymbolsManager()
	{
		FreeSymbols();
	}

	bool InitSymbols(HANDLE _hProcess, bool enableAutoDownload)
	{
		if (!_hProcess || _hProcess == INVALID_HANDLE_VALUE) {
			return false;
		}
		isInit = InitSymbolsWithPath(_hProcess, enableAutoDownload);
		if (!isInit) {
			if (InitDbgHelpSession(_hProcess, nullptr)) {
				isInit = true;
			}
		}
		if (isInit) {
			hProcess = _hProcess;
		}
		return isInit;
	}
	
	bool IsInitialized()
	{
		return isInit;
	}

	bool RefreshModules()
	{
		if (!isInit || !hProcess)
			return false;

		return SymRefreshModuleList(hProcess) == TRUE;
	}

	//---
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

	std::string funcNameFromAddr(IN const ULONG_PTR addr, OUT OPTIONAL size_t* displacement = nullptr)
	{
		if (!IsInitialized()) {
			return "";
		}
		CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;

		DWORD64 Displacement = 0;
		
		if (!SymFromAddr(hProcess, addr, &Displacement, pSymbol)) {
			return "";
		}
		if (displacement) {
			(*displacement) = static_cast<size_t>(Displacement);
		}
		std::string funcName(pSymbol->Name);
		NormalizeNtZwPrefix(funcName);
		return funcName;
	}

	bool dumpSymbolInfo(const ULONG_PTR addr)
	{
		if (!IsInitialized()) return false;

		CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;

		DWORD64 Displacement = 0;
		BOOLEAN result = SymFromAddr(hProcess, addr, &Displacement, pSymbol);
		std::cout << std::dec << "[" << GetProcessId(hProcess) << "] " << std::hex << addr;
		if (result) {
			std::cout << " Sym: " << pSymbol->TypeIndex << " Base: " << pSymbol->ModBase << " : " << pSymbol->Name << " +0x" << std::hex << Displacement
			//std::cout << " Sym: " << pSymbol->ModBase << " : " << pSymbol->Name << " disp: " << Displacement
				<< " Flags: " << pSymbol->Flags << " Tag: " << pSymbol->Tag << std::endl;
			if (pSymbol->Flags == SYMFLAG_CLR_TOKEN) std::cout << " CLR token!\n";
		}
		else {
			std::cout << " UNK \n";
		}
		return result == TRUE;
	}

protected:
	bool FreeSymbols()
	{
		if (!isInit) return true;
		if (SymCleanup(hProcess)) {
			isInit = false;
			return true;
		}
		return false;
	}

	HANDLE hProcess;
	bool isInit;
};
