#pragma once

#include <windows.h>

#include <map>
#include <string>
#include <iostream>


struct LoadedModule {

	LoadedModule(DWORD _pid, ULONGLONG _start, size_t _moduleSize)
		: process_id(_pid), start(_start), end(_start + _moduleSize),
		is_suspicious(false)
	{
	}

	~LoadedModule()
	{
	}

	bool operator<(LoadedModule other) const
	{
		return this->start < other.start;
	}

	void setSuspicious(bool _is_suspicious) {
		this->is_suspicious = _is_suspicious;
	}

	bool isSuspicious() const
	{
		return this->is_suspicious;
	}
	
	const ULONGLONG start;
	const ULONGLONG end;
	const DWORD process_id;

private:
	bool is_suspicious;
};

struct ProcessModules {
	ProcessModules (DWORD _pid)
		: process_id(_pid)
	{
	}

	~ProcessModules()
	{
		deleteAll();
	}

	bool appendModule(LoadedModule* module);
	void deleteAll();

	LoadedModule* getModuleContaining(ULONGLONG address, size_t size = 0) const;
	LoadedModule* getModuleAt(ULONGLONG address) const;

	const DWORD process_id;

private:
	std::map<ULONGLONG, LoadedModule*> modulesMap;
};
