#pragma once

#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp")

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

	bool InitSymbols(HANDLE _hProcess)
	{
		if (!_hProcess || _hProcess == INVALID_HANDLE_VALUE) {
			return false;
		}
		if (!isInit) {
			hProcess = _hProcess;
			SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEBUG | SYMOPT_INCLUDE_32BIT_MODULES);
			if (SymInitialize(hProcess, NULL, TRUE)) {
				isInit = true;
			}
		}
		return isInit;
	}
	
	bool IsInitialized()
	{
		return isInit;
	}

	//---

	bool dumpSymbolInfo(ULONG_PTR addr)
	{
		if (!isInit) return false;

		CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;
		DWORD64 Displacement = { 0 };

		BOOLEAN result = SymFromAddr(hProcess, addr, &Displacement, pSymbol);
		if (result) {
			std::cout << std::dec << "[" << GetProcessId(hProcess) << "]" << std::hex << addr << " Sym: " << pSymbol->ModBase << " : " << pSymbol->Name << " disp: " << Displacement
				<< " Flags: " << pSymbol->Flags << " Tag: " << pSymbol->Tag << std::endl;
			if (pSymbol->Flags == SYMFLAG_CLR_TOKEN) std::cout << "CLR token!\n";
		}
		else {
			std::cout << std::dec << "[" << GetProcessId(hProcess) << "]" << std::hex << addr << " UNK \n";
		}
		return true;
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
