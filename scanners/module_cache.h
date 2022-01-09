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
#ifdef _DEBUG
			std::cout << "Created buffer cache:  " << std::hex << (ULONG_PTR)moduleData << " \n";
#endif
			moduleSize = _moduleSize;
		}

		BYTE* makeCacheCopy(size_t &copySize) const
		{
			if (!moduleData || !moduleSize) return nullptr;

			BYTE* buf_copy = peconv::alloc_aligned(moduleSize, PAGE_READWRITE);
			if (!buf_copy) return nullptr;
#ifdef _DEBUG
			std::cout << "Copying moduleData:  "<< std::hex << (ULONG_PTR)moduleData << " \n";
#endif
			memcpy(buf_copy, moduleData, moduleSize);
			copySize = moduleSize;
#ifdef _DEBUG
			std::cout << "Copied: "<< copySize << "\n";
#endif
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
		
		static const size_t MinCacheCntr = 3;

		ModulesCache()
		{
			std::cout << "Cache initialized\n";
		}

		~ModulesCache()
		{
			std::lock_guard<std::mutex> guard(cacheMutex);

			std::map<std::string, CachedModule*>::iterator itr;
			for (itr = cachedModules.begin(); itr != cachedModules.end(); ++itr) {
				std::cout << "Deleting cached module: " << itr->first << "\n";
				CachedModule* cached = itr->second;
				delete cached;
			}
			cachedModules.clear();
			std::cout << "Cache deleted\n";
		}

		BYTE* loadCached(LPSTR szModName, size_t& original_size)
		{
			BYTE* mod_buf = getCached(szModName, original_size);
			if (mod_buf) {
#ifdef _DEBUG
				std::cout << "Got module from cache: " << szModName << "\n";
#endif
				return mod_buf;
			}
				
			mod_buf = peconv::load_pe_module(szModName, original_size, false, false);
			// Add to cache if needed...
			{
				std::lock_guard<std::mutex> guard(cacheMutex);
				size_t currCntr = usageCounter[szModName]++;
				if (mod_buf && currCntr >= MinCacheCntr) {
					CachedModule* cached = new(std::nothrow) CachedModule(mod_buf, original_size);
					if (cached) {
						if (cached->moduleData) {
							cachedModules[szModName] = cached;
						}
						else {
							delete cached;
						}
					}
				}
			}
			//
			return mod_buf;
		}

	protected:


		BYTE* getCached(const std::string &modName, size_t& cacheSize)
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


		//< how many times loading of the same module was requested
		std::map<std::string, size_t> usageCounter;

		std::map<std::string, CachedModule*> cachedModules;

		std::mutex cacheMutex;
	};

};