#include "scanned_modules.h"

#include <string>
#include <iostream>

bool ProcessModules::appendModule(LoadedModule* lModule)
{
	if (lModule == nullptr) {
		return false;
	}
	ULONGLONG start_addr = lModule->start;
	if (this->modulesMap.find(start_addr) != this->modulesMap.end()) {
		return false;
	}
	modulesMap[start_addr] = lModule;
	return true;
}

void ProcessModules::deleteAll()
{
	std::map<ULONGLONG, LoadedModule*>::iterator itr = modulesMap.begin();
	for (; itr != modulesMap.end(); itr++ ) {
		const LoadedModule *module = itr->second;
		delete module;
	}
	this->modulesMap.clear();
}

LoadedModule* ProcessModules::getModuleContaining(ULONGLONG address)
{
	std::map<ULONGLONG, LoadedModule*>::iterator start_itr = modulesMap.begin();
	std::map<ULONGLONG, LoadedModule*>::iterator stop_itr = modulesMap.upper_bound(address);
	std::map<ULONGLONG, LoadedModule*>::iterator itr = start_itr;
	for (; itr != stop_itr; itr++ ) {
		LoadedModule *module = itr->second;

		if (address >= module->start && address < module->end) {
#ifdef _DEBUG
			std::cout << "Addr: " << std::hex << address << " found in: " << module->start << " - " << module->end << std::endl;
#endif
			return module;
		}
	}
	return nullptr;
}

LoadedModule* ProcessModules::getModuleAt(ULONGLONG address)
{
	std::map<ULONGLONG, LoadedModule*>::iterator itr = modulesMap.find(address);
	if (itr != modulesMap.end()) {
		return itr->second;
	}
	return nullptr;
}

