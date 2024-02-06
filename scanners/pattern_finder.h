#pragma once

#include <windows.h>
#include <sstream>

#include <sig_finder.h>

namespace pesieve {

	sig_ma::matched_set find_matching_patterns(BYTE* loadedData, size_t loadedSize, bool stopOnFirstMatch = true);

};
