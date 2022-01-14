#include "module_cache.h"

BYTE* pesieve::ModulesCache::_loadRawCached(LPSTR szModName, size_t& original_size)
{
	BYTE* raw_buf = _getCached(szModName, original_size);
	if (raw_buf) {
#ifdef _DEBUG
		std::cout << "Reading from cache: " << szModName << "\n";
#endif
		return raw_buf;
	}

	raw_buf = peconv::load_file(szModName, original_size);
	// Add to cache if needed...
	{
		std::lock_guard<std::mutex> guard(cacheMutex);
		size_t currCntr = usageCounter[szModName]++;
		size_t cachedModulesCntr = cachedModules.size();
		if (raw_buf && currCntr >= MinUsageCntr && cachedModulesCntr < MaxCachedModules) {
			CachedModule* cached = new(std::nothrow) CachedModule(raw_buf, original_size);
			if (cached) {
				if (cached->moduleData) {
					cachedModules[szModName] = cached;
#ifdef _DEBUG
					std::cout << "Added to cache: " << szModName << "\n";
#endif
				}
				else {
					delete cached;
				}
			}
		}
	}
	return raw_buf;
}

BYTE* pesieve::ModulesCache::loadCached(LPSTR szModName, size_t& module_size)
{
	size_t raw_size = 0;
	BYTE* raw_buf = _loadRawCached(szModName, raw_size);
	if (!raw_buf) {
		return nullptr; // failed to load file
	}
	BYTE* my_pe = peconv::load_pe_module(raw_buf, raw_size, module_size, false, false);
	peconv::free_file(raw_buf);
	return my_pe;
}
