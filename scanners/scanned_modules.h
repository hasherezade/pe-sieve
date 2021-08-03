#pragma once

#include <windows.h>

#include <map>
#include <string>
#include <iostream>

#include "module_scan_report.h"

namespace pesieve {

	//!  Represents a basic info about the scanned module, such as its base offset, size, and the status.
	class ScannedModule {

	public:

		ULONGLONG getStart() const
		{
			return start;
		}

		ULONGLONG getEnd() const
		{
			return moduleSize + start;
		}

		size_t getSize()
		{
			return moduleSize;
		}

		bool isSuspicious() const
		{
			return this->is_suspicious;
		}
		
		std::string getModName() const
		{
			return this->moduleName;
		}

	protected:
		ScannedModule(ULONGLONG _start, size_t _moduleSize)
			: start(_start), moduleSize(_moduleSize),
			is_suspicious(false)
		{
		}

		~ScannedModule()
		{
		}

		bool operator<(ScannedModule other) const
		{
			return this->start < other.start;
		}

		void setSuspicious(bool _is_suspicious) {
			this->is_suspicious = _is_suspicious;
		}

		bool resize(size_t newSize)
		{
			if (moduleSize < newSize) {
				//std::cout << "Resizing module from: " << std::hex << moduleSize << " to: " << newSize << "\n";
				moduleSize = newSize;
				return true;
			}
			return false;
		}

		const ULONGLONG start;

	private:
		size_t moduleSize;
		bool is_suspicious;
		std::string moduleName;

		friend class ModulesInfo;
	};

	//!  A container of all the process modules that were scanned.
	class ModulesInfo {

	public:
		ModulesInfo(DWORD _pid)
			: process_id(_pid)
		{
		}

		~ModulesInfo()
		{
			deleteAll();
		}

		bool appendToModulesList(ModuleScanReport *report);

		size_t count() { return modulesMap.size(); }

		size_t getScannedSize(ULONGLONG start_address) const;
		ScannedModule* findModuleContaining(ULONGLONG address, size_t size = 0) const;
		ScannedModule* getModuleAt(ULONGLONG address) const;

	protected:
		bool appendModule(ScannedModule* module);
		void deleteAll();

	private:
		std::map<ULONGLONG, ScannedModule*> modulesMap;
		const DWORD process_id;
	};

}; //namespace pesieve

