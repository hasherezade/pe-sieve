#include "strings_util.h"

#include <algorithm>
#include <cstring>

std::string pesieve::util::to_lowercase(std::string str)
{
	std::transform(str.begin(), str.end(), str.begin(), tolower);
	return str;
}

bool pesieve::util::is_cstr_equal(char const *a, char const *b, const size_t max_len)
{
	for (size_t i = 0; i < max_len; ++i) {
		if (tolower(a[i]) != tolower(b[i])) {
			return false;
		}
		if (tolower(a[i]) == '\0') break;
	}
	return true;
}
