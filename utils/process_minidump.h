#pragma once
#include <windows.h>
#include <string>

namespace pesieve {
	namespace util {

		bool make_minidump(DWORD pid, const std::string &out_file);
	};
};
