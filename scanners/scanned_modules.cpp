#include "scanned_modules.h"

#include <string>
#include <iostream>

using namespace pesieve;

bool pesieve::ProcessModules::appendModule(LoadedModule* lModule)
{
	if (lModule == nullptr) {
		return false;
	}
	ULONGLONG start_addr = lModule->start;
	if (this->modulesMap.find(start_addr) != this->modulesMap.end()) {
		//already exist
		return false;
	}
	modulesMap[start_addr] = lModule;
	return true;
}

void pesieve::ProcessModules::deleteAll()
{
	std::map<ULONGLONG, LoadedModule*>::iterator itr = modulesMap.begin();
	for (; itr != modulesMap.end(); ++itr ) {
		const LoadedModule *module = itr->second;
		delete module;
	}
	this->modulesMap.clear();
}

size_t pesieve::ProcessModules::getScannedSize(ULONGLONG address) const
{
	std::map<ULONGLONG, LoadedModule*>::const_iterator start_itr = modulesMap.begin();
	std::map<ULONGLONG, LoadedModule*>::const_iterator stop_itr = modulesMap.upper_bound(address);
	std::map<ULONGLONG, LoadedModule*>::const_iterator itr = start_itr;

	size_t max_size = 0;

	for (; itr != stop_itr; ++itr) {
		LoadedModule *module = itr->second;
		if (address >= module->start && address < module->getEnd()) {
			ULONGLONG diff = module->getEnd() - address;
			if (diff > max_size) {
				max_size = diff;
			}
		}
	}
	return max_size;
}

LoadedModule* pesieve::ProcessModules::getModuleContaining(ULONGLONG address, size_t size) const
{
	std::map<ULONGLONG, LoadedModule*>::const_iterator start_itr = modulesMap.begin();
	std::map<ULONGLONG, LoadedModule*>::const_iterator stop_itr = modulesMap.upper_bound(address);
	std::map<ULONGLONG, LoadedModule*>::const_iterator itr = start_itr;
	
	const ULONGLONG end_addr = (size > 0)? address + (size - 1) : address;

	for (; itr != stop_itr; ++itr ) {
		LoadedModule *module = itr->second;
		if (address >= module->start && end_addr < module->getEnd()) {
#ifdef _DEBUG
			std::cout << "Addr: " << std::hex << address << " found in: " << module->start << " - " << module->getEnd() << std::endl;
#endif
			return module;
		}
	}
	return nullptr;
}

LoadedModule* pesieve::ProcessModules::getModuleAt(ULONGLONG address) const
{
	std::map<ULONGLONG, LoadedModule*>::const_iterator itr = modulesMap.find(address);
	if (itr != modulesMap.end()) {
		return itr->second;
	}
	return nullptr;
}

