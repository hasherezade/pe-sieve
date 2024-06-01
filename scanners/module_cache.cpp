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
		const bool is_cache_available = isCacheAvailable(raw_size);
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
	prepareCacheSpace(raw_size, force_free_cache);

	// return the mapped module:
	mapped_pe = peconv::load_pe_module(raw_buf, raw_size, module_size, false, false);
	peconv::free_file(raw_buf);
	return mapped_pe;
}

bool pesieve::ModulesCache::isCacheAvailable(const size_t neededSize)
{
	bool hasFree = false;
	SIZE_T minSize = 0;
	SIZE_T maxSize = 0;
	DWORD info = 0;

	if (!GetProcessWorkingSetSizeEx(GetCurrentProcess(), &minSize, &maxSize, &info)) {
#ifdef _DEBUG
		std::cout << "GetProcessWorkingSetSizeEx failed!\n";
#endif
		return false;
	}

	MEMORYSTATUSEX memStatus = { 0 };
	memStatus.dwLength = sizeof(MEMORYSTATUSEX);

	if ((info & QUOTA_LIMITS_HARDWS_MAX_DISABLE) == QUOTA_LIMITS_HARDWS_MAX_DISABLE) { // The working set may exceed the maximum working set limit if there is abundant memory
		if (GlobalMemoryStatusEx(&memStatus)) {
			if (memStatus.ullAvailVirtual > ((DWORDLONG)neededSize * 2) && (memStatus.dwMemoryLoad < 50)) {
				hasFree = true;
			}
		}
	}

	PROCESS_MEMORY_COUNTERS ppsmemCounter = { 0 };
	ppsmemCounter.cb = sizeof(PROCESS_MEMORY_COUNTERS);
	GetProcessMemoryInfo(GetCurrentProcess(), &ppsmemCounter, sizeof(PROCESS_MEMORY_COUNTERS));

	// hard limit is enabled, use it to calculate how much you can use
	if (maxSize > ppsmemCounter.PeakWorkingSetSize) {
		size_t freeMem = maxSize - ppsmemCounter.WorkingSetSize;
		size_t percW1 = size_t(((double)ppsmemCounter.WorkingSetSize / (double)maxSize) * 100.0);
		if (freeMem > (neededSize * 2) && (percW1 < 60)) {
			hasFree = true;
		}
	}
	size_t freeMemP = ppsmemCounter.PeakWorkingSetSize - ppsmemCounter.WorkingSetSize;
	size_t percPeak = size_t(((double)ppsmemCounter.WorkingSetSize / (double)ppsmemCounter.PeakWorkingSetSize) * 100.0);

	if (freeMemP > (neededSize * 2) && (percPeak < 70)) {
		hasFree = true;
	}

#ifdef _DEBUG
	if (!hasFree) {
		std::cout << "C: " << std::hex << ppsmemCounter.WorkingSetSize
			<< "\tP: " << std::hex << ppsmemCounter.PeakWorkingSetSize
			<< "\tMin: " << minSize
			<< "\tMax: " << maxSize
			<< "\tGlobalMem Av Virt: " << std::hex << memStatus.ullAvailVirtual
			<< std::dec << "\tPerc: " << memStatus.dwMemoryLoad
			<< std::dec << "  PercPeak: " << percPeak
			<< " HasFree: " << hasFree
			<< " modulesCount: " << cachedModules.size() 
			<< std::endl;
	}
#endif
	return hasFree;
}
