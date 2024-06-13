#pragma once

#include <peconv.h>
#include <string>
#include <map>
#include "../utils/custom_mutex.h"

namespace pesieve
{
	struct CachedModule {
	public:
		CachedModule() 
			: moduleData(nullptr), moduleSize(0), lastUsage(0)
		{
		}

		CachedModule(BYTE* _moduleData, size_t _moduleSize)
			: moduleData(nullptr), moduleSize(0), lastUsage(0)
		{
			moduleData = peconv::alloc_unaligned(_moduleSize);
			if (!moduleData) return;

			memcpy(moduleData, _moduleData, _moduleSize);
			moduleSize = _moduleSize;
			lastUsage = GetTickCount();
		}

		BYTE* mapFromCached(size_t &mappedSize) const
		{
			if (!this->moduleData || !this->moduleSize) return nullptr;

			BYTE* my_pe = peconv::load_pe_module(moduleData, moduleSize, mappedSize, false, false);
			return my_pe;
		}

		~CachedModule()
		{
#ifdef _DEBUG
			std::cout << "Deleting cached module...\n";
#endif
			peconv::free_unaligned(moduleData);
			moduleData = nullptr;
			moduleSize = 0;
		}
		
		BYTE* moduleData;
		size_t moduleSize;
		DWORD lastUsage;
	};


	class ModulesCache {

	public:
		
		static const size_t MinUsageCntr = 2; ///< how many times loading of the module must be requested before the module is added to cache

		ModulesCache()
		{
#ifdef _DEBUG
			std::cout << "Cache initialized\n";
#endif
		}

		~ModulesCache()
		{
			deleteCache();
		}

		BYTE* loadCached(LPSTR szModName, size_t& original_size);

	protected:
		BYTE* getMappedCached(const std::string &modName, size_t& mappedSize)
		{
			util::MutexLocker guard(cacheMutex);

			std::map<std::string, CachedModule*>::iterator itr = cachedModules.find(modName);
			if (itr != cachedModules.end()) {
				CachedModule* cached = itr->second;
				if (!cached) return nullptr;
				
				cached->lastUsage = GetTickCount();
				return cached->mapFromCached(mappedSize);
			}
			return nullptr;
		}

		bool isCacheAvailable(const size_t neededSize);

		bool prepareCacheSpace(const size_t neededSize, bool force_free)
		{
			util::MutexLocker guard(cacheMutex);
			if (force_free) {
				_deleteLeastRecent();
			}
			while (!isCacheAvailable(neededSize)) {
				if (!_deleteLeastRecent()) {
					return false; // cannot make free space
				}
			}
			return true;
		}

		bool _deleteLeastRecent()
		{
			DWORD lTimestamp = 0;
			DWORD gTimestamp = 0;
			std::map<std::string, CachedModule*>::iterator foundItr = cachedModules.end();

			std::map<std::string, CachedModule*>::iterator itr;
			for (itr = cachedModules.begin(); itr != cachedModules.end(); ++itr) {
				CachedModule* mod = itr->second;
				if (!mod) continue;

				if ((lTimestamp == 0) || (mod->lastUsage < lTimestamp)) {
					lTimestamp = mod->lastUsage;
					foundItr = itr;
				}

				if ((gTimestamp == 0) || (mod->lastUsage > gTimestamp)) {
					gTimestamp = mod->lastUsage;
				}
			}

			if ((gTimestamp == lTimestamp) || (foundItr == cachedModules.end())) {
				return false; // nothing to remove
			}
#ifdef _DEBUG
			std::cout << "Deleting the least recent module: " << foundItr->first << " timestamp: " << lTimestamp << "\n";
#endif
			// remove the module that was used the least recently:
			usageBeforeCounter[foundItr->first] = 0;
			CachedModule* mod1 = foundItr->second;
			delete mod1;
			cachedModules.erase(foundItr);
			return true;
		}

		void deleteCache()
		{
			util::MutexLocker guard(cacheMutex);

			std::map<std::string, CachedModule*>::iterator itr;
#ifdef _DEBUG
			size_t i = 0;
#endif
			for (itr = cachedModules.begin(); itr != cachedModules.end(); ++itr) {
#ifdef _DEBUG
				std::cout << "[" << i++ << "] Deleting cached module: " << itr->first << "\n";
#endif
				CachedModule* cached = itr->second;
				delete cached;
			}
			cachedModules.clear();
			usageBeforeCounter.clear();
#ifdef _DEBUG
			std::cout << "Cache deleted. Total: " << i << " modules.\n";
#endif
		}

		std::map<std::string, size_t> usageBeforeCounter; ///< how many times loading of the same module was requested before it was cached

		std::map<std::string, CachedModule*> cachedModules; ///< the list of all the cached modules

		util::Mutex cacheMutex;
	};

};
