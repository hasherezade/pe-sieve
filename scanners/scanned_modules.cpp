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
		mod = new ScannedModule(module_start, report->moduleSize);
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

ScannedModule* pesieve::ModulesInfo::findModuleContaining(ULONGLONG address, size_t size) const
{
	const ULONGLONG field_end = address + size;

	// the first element that is greater than the start address
	std::map<ULONGLONG, ScannedModule*>::const_iterator firstGreater = modulesMap.upper_bound(address);

	std::map<ULONGLONG, ScannedModule*>::const_iterator itr;
	for (itr = modulesMap.begin(); itr != firstGreater; ++itr) {
		ScannedModule *module = itr->second;
		if (!module) continue; //this should never happen

		if (address >= module->getStart() && field_end <= module->getEnd()) {
			// Address found in module:
			return module;
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

ScannedModule* pesieve::ModulesInfo::getModuleAt(ULONGLONG address) const
{
	std::map<ULONGLONG, ScannedModule*>::const_iterator itr = modulesMap.find(address);
	if (itr != modulesMap.end()) {
		return itr->second;
	}
	return nullptr;
}

