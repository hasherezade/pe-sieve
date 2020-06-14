#pragma once

#include <windows.h>

#include <map>
#include <string>
#include <iostream>

namespace pesieve {

	struct LoadedModule {

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

		bool isSuspicious() const
		{
			return this->is_suspicious;
		}

		ULONGLONG getEnd() const
		{
			return moduleSize + start;
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

		size_t getSize()
		{
			return moduleSize;
		}

		const ULONGLONG start;
		const DWORD process_id;

	private:
		size_t moduleSize;
		bool is_suspicious;
	};

	struct ProcessModules {
		ProcessModules(DWORD _pid)
			: process_id(_pid)
		{
		}

		~ProcessModules()
		{
			deleteAll();
		}

		bool appendModule(LoadedModule* module);
		void deleteAll();

		size_t getScannedSize(ULONGLONG start_address) const;
		LoadedModule* getModuleContaining(ULONGLONG address, size_t size = 0) const;
		LoadedModule* getModuleAt(ULONGLONG address) const;

		const DWORD process_id;

	private:
		std::map<ULONGLONG, LoadedModule*> modulesMap;
	};

}; //namespace pesieve

