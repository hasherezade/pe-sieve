#pragma once

#include <Windows.h>

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

	ULONGLONG start;
	ULONGLONG end;
	DWORD process_id;
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

	LoadedModule* getModuleContaining(ULONGLONG address);
	LoadedModule* getModuleAt(ULONGLONG address);

	std::map<ULONGLONG, LoadedModule*> modulesMap;
	DWORD process_id;
};
