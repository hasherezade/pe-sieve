#pragma once

#include <string>

namespace pesieve {

	namespace util {

		std::string to_lowercase(std::string);

		// Compare cstrings (ignore case)
		bool is_cstr_equal(char const *a, char const *b, const size_t max_len);

	};
};
