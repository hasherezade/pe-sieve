#pragma once

#include <windows.h>
#include <string>

namespace pesieve {
	namespace util {

		void print_in_color(int color, const std::string &text, bool is_error=false);
	};
};
