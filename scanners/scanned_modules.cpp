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

bool pesieve::ProcessModules::appendToModulesList(ModuleScanReport *report)
{
	if (!report || report->moduleSize == 0) {
		return false; //skip
	}
	ULONGLONG module_start = (ULONGLONG)report->module;
	LoadedModule* mod = this->getModuleAt(module_start);
	if (mod == nullptr) {
		//create new only if it was not found
		mod = new LoadedModule(report->pid, module_start, report->moduleSize);
		if (!this->appendModule(mod)) {
			delete mod; //delete the module as it was not appended
			return false;
		}
	}
	size_t old_size = mod->getSize();
	if (old_size < report->moduleSize) {
		mod->resize(report->moduleSize);
	}
	if (!mod->isSuspicious()) {
		//update the status
		mod->setSuspicious(report->status == SCAN_SUSPICIOUS);
	}
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
			// Address found in module:
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

