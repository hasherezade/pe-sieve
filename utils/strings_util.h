#pragma once

#include <string>

namespace pesieve {

	namespace util {
		
		std::string to_lowercase(std::string);

		// Compare cstrings (ignore case)
		bool is_cstr_equal(char const *a, char const *b, const size_t max_len);

		// Calculate Levenshtein distance of two strings
		size_t levenshtein_distance(const char s1[], const char s2[]);

		// Calculate a diffrence in strings histograms
		size_t str_hist_diffrence(const char s1[], const char s2[]);
	};
};
