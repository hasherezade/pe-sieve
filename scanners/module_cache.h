#pragma once

#include <peconv.h>
#include <string>
#include <map>
#include <mutex>

namespace pesieve
{

	struct CachedModule {
	public:
		CachedModule() : moduleData(nullptr), moduleSize(0)
		{
		}

		CachedModule(BYTE* _moduleData, size_t _moduleSize)
			: moduleData(nullptr), moduleSize(0)
		{
			moduleData = peconv::alloc_unaligned(_moduleSize);
			if (!moduleData) return;

			memcpy(moduleData, _moduleData, _moduleSize);
			moduleSize = _moduleSize;
		}

		BYTE* makeCacheCopy(size_t &copySize) const
		{
			if (!moduleData || !moduleSize) return nullptr;

			BYTE* buf_copy = peconv::alloc_unaligned(moduleSize);
			if (!buf_copy) return nullptr;

			memcpy(buf_copy, moduleData, moduleSize);
			copySize = moduleSize;
			return buf_copy;
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
		
		BYTE* moduleData = nullptr;
		size_t moduleSize = 0;
	};


	class ModulesCache {

	public:
		
		static const size_t MinUsageCntr = 3; ///< how many times loading of the module must be requested before the module is added to cache
		static const size_t MaxCachedModules = 1000; ///< how many modules can be stored in the cache at the time

		ModulesCache()
		{
#ifdef _DEBUG
			std::cout << "Cache initialized\n";
#endif
		}

		~ModulesCache()
		{
			_deleteCache();
		}

		BYTE* loadCached(LPSTR szModName, size_t& original_size);

	protected:

		BYTE* _loadRawCached(LPSTR szModName, size_t& original_size);

		BYTE* _getCached(const std::string &modName, size_t& cacheSize)
		{
			std::lock_guard<std::mutex> guard(cacheMutex);

			std::map<std::string, CachedModule*>::iterator itr = cachedModules.find(modName);
			if (itr != cachedModules.end()) {
				const CachedModule* cached = itr->second;
				if (!cached) return nullptr;

				return cached->makeCacheCopy(cacheSize);
			}
			return nullptr;
		}

		void _deleteCache()
		{
			std::lock_guard<std::mutex> guard(cacheMutex);

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
			usageCounter.clear();
#ifdef _DEBUG
			std::cout << "Cache deleted. Total: " << i << " modules.\n";
#endif
		}

		std::map<std::string, size_t> usageCounter; ///< how many times loading of the same module was requested before it was cached

		std::map<std::string, CachedModule*> cachedModules; ///< the list of all the cached modules

		std::mutex cacheMutex;
	};

};
