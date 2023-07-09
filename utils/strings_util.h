#pragma once

#include <string>

namespace pesieve {

	#define IS_ENDLINE(c) (c == 0x0A || c == 0xD)
	#define IS_PRINTABLE(c) ((c >= 0x20 && c < 0x7f) || IS_ENDLINE(c))

	namespace util {

		std::string to_lowercase(std::string);

		// Compare cstrings (ignore case)
		bool is_cstr_equal(char const *a, char const *b, const size_t max_len);

	};
};
