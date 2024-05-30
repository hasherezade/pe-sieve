#include "module_cache.h"
#include <psapi.h>

BYTE* pesieve::ModulesCache::loadCached(LPSTR szModName, size_t& module_size)
{
	BYTE *mapped_pe = getMappedCached(szModName, module_size);
	if (mapped_pe) {
		return mapped_pe; // retrieved from cache
	}
	size_t raw_size = 0;
	BYTE* raw_buf = peconv::load_file(szModName, raw_size);
	if (!raw_buf) {
		return nullptr; // failed to load the file
	}

	bool force_free_cache = false;
	// Add to cache if needed...
	{
		util::MutexLocker guard(cacheMutex);
		size_t currCntr = usageBeforeCounter[szModName]++;
		const size_t cachedModulesCntr = cachedModules.size();
		const bool is_cache_available = isCacheAvailable();
		if (currCntr >= MinUsageCntr && is_cache_available) {
			bool is_cached = false;
			CachedModule* mod_cache = new(std::nothrow) CachedModule(raw_buf, raw_size);
			if (mod_cache) {
				if (mod_cache->moduleData) {
					cachedModules[szModName] = mod_cache;
					is_cached = true;
#ifdef _DEBUG
					std::cout << "Added to cache: " << szModName << " Total cached: " << cachedModulesCntr << "\n";
#endif
				}
			}
			if (!is_cached) {
				delete mod_cache;
				// possibly running out of memory, make sure to free some cache:
				force_free_cache = true;
			}
		}
	}

	// after adding file to the cache, wipe out the old ones:
	prepareCacheSpace(force_free_cache);

	// return the mapped module:
	mapped_pe = peconv::load_pe_module(raw_buf, raw_size, module_size, false, false);
	peconv::free_file(raw_buf);
	return mapped_pe;
}

size_t pesieve::ModulesCache::checkFreeMemory()
{
	SIZE_T minSize = 0;
	SIZE_T maxSize = 0;
	DWORD info = 0;
	GetProcessWorkingSetSizeEx(GetCurrentProcess(), &minSize, &maxSize, &info);

	MEMORYSTATUSEX memStatus = { 0 };
	memStatus.dwLength = sizeof(MEMORYSTATUSEX);

	if ((info & QUOTA_LIMITS_HARDWS_MAX_DISABLE) == QUOTA_LIMITS_HARDWS_MAX_DISABLE) {
		GlobalMemoryStatusEx(&memStatus);
	}

	PROCESS_MEMORY_COUNTERS ppsmemCounter = { 0 };
	ppsmemCounter.cb = sizeof(PROCESS_MEMORY_COUNTERS);
	GetProcessMemoryInfo(GetCurrentProcess(), &ppsmemCounter, sizeof(PROCESS_MEMORY_COUNTERS));
#ifdef _DEBUG
	std::cout << "C: " << std::hex << ppsmemCounter.WorkingSetSize
		<< "\tP: " << std::hex << ppsmemCounter.PeakWorkingSetSize
		<< "\tMin: " << minSize
		<< "\tMax: " << maxSize
		<< "\tGlobalMem Av Virt: " << std::hex << memStatus.ullAvailVirtual
		<< std::dec << "\tPerc: " << memStatus.dwMemoryLoad
		<< std::endl;
#endif
	return memStatus.dwMemoryLoad;
}