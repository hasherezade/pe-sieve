#include "artefacts_util.h"
#include <peconv.h>
#include "code_patterns.h"
#ifdef _DEBUG
	#include <iostream>
#endif

using namespace sig_finder;

BYTE* pesieve::util::find_pattern(BYTE* buffer, size_t buf_size, BYTE* pattern_buf, size_t pattern_size, size_t max_iter)
{
	for (size_t i = 0; (i + pattern_size) < buf_size; i++) {
		if (max_iter != 0 && i > max_iter) break;
		if (memcmp(buffer + i, pattern_buf, pattern_size) == 0) {
			return (buffer + i);
		}
	}
	return nullptr;
}

namespace pesieve {

	std::set<DWORD> HardcodedPatterns;
	pesieve::util::Mutex g_HardcodedPatternsMutex;

	size_t init_32_patterns(Node* rootN)
	{
		util::MutexLocker guard(g_HardcodedPatternsMutex);
		if (!rootN) return 0;

		size_t added = 0;
		for (size_t i = 0; i < _countof(patterns32); i++)
		{
			const t_pattern& pattern = patterns32[i];
			std::string name = "prolog32_" + std::to_string((ULONGLONG)i);
			Signature sign(name, pattern.ptr, pattern.size);
			if (rootN->addPattern(sign)) {
				HardcodedPatterns.insert(sign.checksum());
				added++;
			}
		}
		return added;
	}

	size_t init_64_patterns(Node* rootN)
	{
		util::MutexLocker guard(g_HardcodedPatternsMutex);
		if (!rootN) return 0;

		size_t added = 0;
		for (size_t i = 0; i < _countof(patterns64); i++)
		{
			const t_pattern &pattern = patterns64[i];
			std::string name = "prolog64_" + std::to_string((ULONGLONG)i);
			Signature sign(name, pattern.ptr, pattern.size);
			if (rootN->addPattern(sign)) {
				HardcodedPatterns.insert(sign.checksum());
				added++;
			}
		}
		return added;
	}

	inline size_t search_till_pattern(sig_finder::Node& rootN, const BYTE* loadedData, size_t loadedSize)
	{
		Match m = sig_finder::find_first_match(rootN, loadedData, loadedSize);
		if (!m.sign) {
			return PATTERN_NOT_FOUND;
		}
		return m.offset;
	}

}; //namespace pesieve

size_t pesieve::util::is_32bit_code(BYTE *loadedData, size_t loadedSize)
{
	static sig_finder::Node rootN;
	if(rootN.isEnd()) {
		init_32_patterns(&rootN);
	}
	return search_till_pattern(rootN, loadedData, loadedSize);
}

size_t pesieve::util::is_64bit_code(BYTE* loadedData, size_t loadedSize)
{
	static sig_finder::Node rootN;
	if (rootN.isEnd()) {
		init_64_patterns(&rootN);
	}
	return search_till_pattern(rootN, loadedData, loadedSize);
}

bool pesieve::util::is_code(BYTE* loadedData, size_t loadedSize)
{
	static sig_finder::Node rootN;
	if (peconv::is_padding(loadedData, loadedSize, 0)) {
		return false;
	}
	if (rootN.isEnd()) {
		init_32_patterns(&rootN);
		init_64_patterns(&rootN);
	}
	if ((search_till_pattern(rootN, loadedData, loadedSize)) != PATTERN_NOT_FOUND) {
		return true;
	}
	return false;
}

bool pesieve::util::is_executable(DWORD mapping_type, DWORD protection)
{
	const bool is_any_exec = (protection & PAGE_EXECUTE_READWRITE)
		|| (protection & PAGE_EXECUTE_READ)
		|| (protection & PAGE_EXECUTE)
		|| (protection & PAGE_EXECUTE_WRITECOPY);
	return is_any_exec;
}

bool pesieve::util::is_readable(DWORD mapping_type, DWORD protection)
{
	const bool is_read = (protection & PAGE_READWRITE)
		|| (protection & PAGE_READONLY);
	return is_read;
}

bool pesieve::util::is_normal_inaccessible(DWORD state, DWORD mapping_type, DWORD protection)
{
	if ((state & MEM_COMMIT) == 0) {
		//not committed
		return false;
	}
	if (mapping_type != MEM_IMAGE && (mapping_type != MEM_MAPPED) && mapping_type != MEM_PRIVATE) {
		// invalid mapping type
		return false;
	}
	if (protection & PAGE_NOACCESS) {
		// inaccessible found
		return true;
	}
	return false;
}

//---
// matcher:

bool pesieve::PatternMatcher::isReady()
{
	util::MutexLocker guard(mainMatcherMutex);
	return (mainMatcher.isEnd()) ? false : true;
}

size_t pesieve::PatternMatcher::loadPatternFile(const char* filename)
{
	util::MutexLocker guard(mainMatcherMutex);
	static bool isLoaded = false;
	if (isLoaded) return 0; // allow to load file only once

	isLoaded = true;
	std::vector<Signature*> signatures;
	Signature::loadFromFile(filename, signatures);
	const size_t added = mainMatcher.addPatterns(signatures);
	// delete the loaded signatures:
	for (auto itr = signatures.begin(); itr != signatures.end(); ++itr) {
		Signature* sign = *itr;
		delete sign;
	}
	std::cout << "Added patterns: " << std::dec << added << "\n";
	return added;
}

bool pesieve::PatternMatcher::initShellcodePatterns()
{
	util::MutexLocker guard(mainMatcherMutex);
	static bool isLoaded = false;
	if (isLoaded) return false; // allow to load only once

	isLoaded = true;
	init_32_patterns(&mainMatcher);
	init_64_patterns(&mainMatcher);
	return true;
}

size_t pesieve::PatternMatcher::findAllPatterns(BYTE* loadedData, size_t loadedSize, std::vector<sig_finder::Match>& allMatches)
{
	if (!isReady()) {
		return false;
	}
	if (peconv::is_padding(loadedData, loadedSize, 0)) {
		return false;
	}
	const size_t matches = sig_finder::find_all_matches(mainMatcher, loadedData, loadedSize, allMatches);
	return matches;
}

size_t pesieve::PatternMatcher::filterCustom(std::vector<sig_finder::Match>& allMatches, std::vector<sig_finder::Match>& customPatternMatches)
{
	util::MutexLocker guard(g_HardcodedPatternsMutex);
	size_t customCount = 0;
	for (auto itr = allMatches.begin(); itr != allMatches.end(); ++itr) {
		sig_finder::Match m = *itr;
		if (m.sign) {
			const DWORD checks = m.sign->checksum();
			if (HardcodedPatterns.find(checks) != HardcodedPatterns.end()) {
				continue;
			}
			customPatternMatches.push_back(m);
			customCount++;
		}
	}
	return customCount;
}
