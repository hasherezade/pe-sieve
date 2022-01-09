#include "module_cache.h"


BYTE* pesieve::ModulesCache::loadCached(LPSTR szModName, size_t& original_size)
{
	BYTE* mod_buf = _getCached(szModName, original_size);
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
		size_t cachedModulesCntr = cachedModules.size();
		if (mod_buf && currCntr >= MinUsageCntr && cachedModulesCntr < MaxCachedModules) {
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