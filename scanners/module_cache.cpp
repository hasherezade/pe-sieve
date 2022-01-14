#include "module_cache.h"

BYTE* pesieve::ModulesCache::loadCached(LPSTR szModName, size_t& module_size)
{
	BYTE *mapped_pe = _getMappedCached(szModName, module_size);
	if (mapped_pe) {
		return mapped_pe; // retrieved from cache
	}
	size_t raw_size = 0;
	BYTE* raw_buf = peconv::load_file(szModName, raw_size);
	if (!raw_buf) {
		return nullptr; // failed to load file
	}
	// Add to cache if needed...
	{
		bool is_cached = false;
		std::lock_guard<std::mutex> guard(cacheMutex);
		size_t currCntr = usageCounter[szModName]++;
		const size_t cachedModulesCntr = cachedModules.size();
		if (raw_buf && currCntr >= MinUsageCntr && cachedModulesCntr < MaxCachedModules) {
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
			}
		}
	}
	mapped_pe = peconv::load_pe_module(raw_buf, raw_size, module_size, false, false);
	peconv::free_file(raw_buf);
	return mapped_pe;
}
