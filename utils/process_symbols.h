#pragma once

#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp")

class ProcessSymbolsManager
{
public:
	ProcessSymbolsManager(HANDLE _hProcess)
		: hProcess(_hProcess), isInit(false)
	{
	}

	~ProcessSymbolsManager()
	{
		FreeSymbols();
	}

	bool InitSymbols()
	{
		if (!isInit) {
			SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEBUG | SYMOPT_INCLUDE_32BIT_MODULES);
			if (SymInitialize(hProcess, NULL, TRUE)) {
				isInit = true;
			}
		}
		return isInit;
	}
	
	//---

	static bool dumpSymbolInfo(HANDLE hProcess, ULONG_PTR addr)
	{
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
			return true;
		}
		return false;
	}

	HANDLE hProcess;
	bool isInit;
};
