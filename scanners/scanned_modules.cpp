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
	for (; itr != modulesMap.end(); ++itr ) {
		const LoadedModule *module = itr->second;
		delete module;
	}
	this->modulesMap.clear();
}

LoadedModule* ProcessModules::getModuleContaining(ULONGLONG address, size_t size) const
{
	std::map<ULONGLONG, LoadedModule*>::const_iterator start_itr = modulesMap.begin();
	std::map<ULONGLONG, LoadedModule*>::const_iterator stop_itr = modulesMap.upper_bound(address);
	std::map<ULONGLONG, LoadedModule*>::const_iterator itr = start_itr;
	
	const ULONGLONG end_addr = (size > 0)? address + (size - 1) : address;

	for (; itr != stop_itr; ++itr ) {
		LoadedModule *module = itr->second;
		if (address >= module->start && end_addr < module->end) {
#ifdef _DEBUG
			std::cout << "Addr: " << std::hex << address << " found in: " << module->start << " - " << module->end << std::endl;
#endif
			return module;
		}
	}
	return nullptr;
}

LoadedModule* ProcessModules::getModuleAt(ULONGLONG address) const
{
	std::map<ULONGLONG, LoadedModule*>::const_iterator itr = modulesMap.find(address);
	if (itr != modulesMap.end()) {
		return itr->second;
	}
	return nullptr;
}

