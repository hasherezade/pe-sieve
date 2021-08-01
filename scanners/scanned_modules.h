#pragma once

#include <windows.h>

#include <map>
#include <string>
#include <iostream>

#include "module_scan_report.h"

namespace pesieve {

	//!  Represents a basic info about the scanned module, such as its base offset, size, and the status.
	class LoadedModule {

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

	protected:
		LoadedModule(DWORD _pid, ULONGLONG _start, size_t _moduleSize)
			: process_id(_pid), start(_start), moduleSize(_moduleSize),
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
		const DWORD process_id;

	private:
		size_t moduleSize;
		bool is_suspicious;

		friend class ProcessModules;
	};

	//!  A container of all the process modules that were scanned.
	class ProcessModules {

	public:
		ProcessModules(DWORD _pid)
			: process_id(_pid)
		{
		}

		~ProcessModules()
		{
			deleteAll();
		}

		bool appendToModulesList(ModuleScanReport *report);
		void deleteAll();

		size_t getScannedSize(ULONGLONG start_address) const;
		LoadedModule* getModuleContaining(ULONGLONG address, size_t size = 0) const;
		LoadedModule* getModuleAt(ULONGLONG address) const;

		const DWORD process_id;

	protected:
		bool appendModule(LoadedModule* module);

	private:
		std::map<ULONGLONG, LoadedModule*> modulesMap;
	};

}; //namespace pesieve

