#include "scanned_modules.h"

#include <string>
#include <iostream>
#include <windows.h>
#include <psapi.h>

using namespace pesieve;

bool pesieve::ModulesInfo::appendModule(ScannedModule* lModule)
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

bool pesieve::ModulesInfo::appendToModulesList(ModuleScanReport *report)
{
	if (!report || report->moduleSize == 0) {
		return false; //skip
	}
	ULONGLONG module_start = (ULONGLONG)report->module;
	ScannedModule* mod = this->getModuleAt(module_start);
	if (mod == nullptr) {
		//create new only if it was not found
		mod = new ScannedModule(report->pid, module_start, report->moduleSize);
		if (!this->appendModule(mod)) {
			delete mod; //delete the module as it was not appended
			return false;
		}
	}
	if (mod->moduleName == "") {
		mod->moduleName = peconv::get_file_name(report->moduleFile);
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

ScannedModule* pesieve::ModulesInfo::findModuleContaining(ULONGLONG searchedAddr)
{
	if (searchedAddr == 0) return nullptr;
#ifdef _DEBUG
	std::cout << "Searching hook address: " << std::hex << searchedAddr << std::endl;
#endif
	std::map<ULONGLONG, ScannedModule*>::iterator itr1;
	std::map<ULONGLONG, ScannedModule*>::iterator lastEl = modulesMap.lower_bound(searchedAddr);
	for (itr1 = modulesMap.begin(); itr1 != lastEl; ++itr1) {
		ScannedModule* modInfo = itr1->second;
		if (!modInfo) continue; //this should never happen

		ULONGLONG begin = modInfo->getStart();
		ULONGLONG end = modInfo->getEnd();
		// searching hook in module:
		if (searchedAddr >= begin && searchedAddr < end) {
			// Address found in module:
			return modInfo;
		}
	}
	return nullptr;
}

void pesieve::ModulesInfo::deleteAll()
{
	std::map<ULONGLONG, ScannedModule*>::iterator itr = modulesMap.begin();
	for (; itr != modulesMap.end(); ++itr ) {
		const ScannedModule *module = itr->second;
		delete module;
	}
	this->modulesMap.clear();
}

size_t pesieve::ModulesInfo::getScannedSize(ULONGLONG address) const
{
	std::map<ULONGLONG, ScannedModule*>::const_iterator start_itr = modulesMap.begin();
	std::map<ULONGLONG, ScannedModule*>::const_iterator stop_itr = modulesMap.upper_bound(address);
	std::map<ULONGLONG, ScannedModule*>::const_iterator itr = start_itr;

	size_t max_size = 0;

	for (; itr != stop_itr; ++itr) {
		ScannedModule *module = itr->second;
		if (address >= module->start && address < module->getEnd()) {
			ULONGLONG diff = module->getEnd() - address;
			if (diff > max_size) {
				max_size = diff;
			}
		}
	}
	return max_size;
}

ScannedModule* pesieve::ModulesInfo::getModuleContaining(ULONGLONG address, size_t size) const
{
	std::map<ULONGLONG, ScannedModule*>::const_iterator start_itr = modulesMap.begin();
	std::map<ULONGLONG, ScannedModule*>::const_iterator stop_itr = modulesMap.upper_bound(address);
	std::map<ULONGLONG, ScannedModule*>::const_iterator itr = start_itr;
	
	const ULONGLONG end_addr = (size > 0)? address + (size - 1) : address;

	for (; itr != stop_itr; ++itr ) {
		ScannedModule *module = itr->second;
		if (address >= module->start && end_addr < module->getEnd()) {
			// Address found in module:
			return module;
		}
	}
	return nullptr;
}

ScannedModule* pesieve::ModulesInfo::getModuleAt(ULONGLONG address) const
{
	std::map<ULONGLONG, ScannedModule*>::const_iterator itr = modulesMap.find(address);
	if (itr != modulesMap.end()) {
		return itr->second;
	}
	return nullptr;
}

