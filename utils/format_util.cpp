#include "format_util.h"

#include <strsafe.h>

#include <sstream>
#include <iomanip>
#include <algorithm>

namespace pesieve {
	namespace util {

		bool is_hex(const char *buf, size_t len)
		{
			for (size_t i = 0; i < len; i++) {
				if (buf[i] >= '0' && buf[i] <= '9') continue;
				if (buf[i] >= 'A' && buf[i] <= 'F') continue;
				if (buf[i] >= 'a' && buf[i] <= 'f') continue;
				return false;
			}
			return true;
		}

		bool is_dec(const char *buf, size_t len)
		{
			for (size_t i = 0; i < len; i++) {
				if (buf[i] >= '0' && buf[i] <= '9') continue;
				return false;
			}
			return true;
		}

	};
};


long pesieve::util::get_number(const char *my_buf)
{
	const char hex_pattern[] = "0x";
	size_t hex_pattern_len = strlen(hex_pattern);

	const size_t len = strlen(my_buf);
	if (len == 0) return 0;

	long out = 0;
	const size_t min_length = 1; //tolerate number with at least 1 character is fine
	if (len > hex_pattern_len) {
		if (strncmp(my_buf, hex_pattern, hex_pattern_len) == 0) {
			if (!is_hex(my_buf + hex_pattern_len, min_length)) return 0;

			out = std::stoul(my_buf, nullptr, 16);
			return out;
		}
	}
	if (!is_dec(my_buf, min_length)) return 0;

	out = std::stoul(my_buf, nullptr, 10);
	return out;
}

bool pesieve::util::is_number(const char* my_buf)
{
	const char hex_pattern[] = "0x";
	size_t hex_pattern_len = strlen(hex_pattern);

	const size_t len = strlen(my_buf);
	if (len == 0) return false;

	if (len > hex_pattern_len) {
		if (strncmp(my_buf, hex_pattern, hex_pattern_len) == 0) {
			if (!is_hex(my_buf + hex_pattern_len, len - hex_pattern_len)) return false;

			return true;
		}
	}
	if (!is_dec(my_buf, len)) return false;
	return true;
}

std::string pesieve::util::to_lowercase(std::string str)
{
	std::transform(str.begin(), str.end(), str.begin(), tolower);
	return str;
}

bool pesieve::util::is_in_list(const char *searched_str, const char *str_list)
{
	const char * list_entry = nullptr;
	bool result = false;

	if (!searched_str || !searched_str[0]) {
		return false;
	}

	for (list_entry = str_list; list_entry && list_entry[0]; list_entry = list_entry + strlen(list_entry) + 1)
	{
		if (!_stricmp(list_entry, searched_str))
		{
			result = true;
			break;
		}
	}
	return result;
}

size_t pesieve::util::delim_list_to_multi_sz(IN const char *delim_list_str, IN const char delimiter, OUT char *buffer, IN const size_t buffer_max_chars)
{
	size_t str_count = 0;
	const char * separator;
	char * buffer_end = buffer + buffer_max_chars - 2;

	// Clear the array
	memset(buffer, 0, buffer_max_chars);

	// Parse the string
	while (delim_list_str && delim_list_str[0])
	{
		// Get the next separator
		separator = strchr(delim_list_str, delimiter);
		if (separator == NULL)
		{
			StringCchCopy(buffer, (buffer_end - buffer), delim_list_str);
			str_count++;
			break;
		}

		// Put the part to the string
		if (separator > delim_list_str)
		{
			StringCchCopyNEx(buffer, (buffer_end - buffer), delim_list_str, (separator - delim_list_str), &buffer, NULL, 0);
			str_count++;
			buffer++;
		}

		// Skip comma and spaces
		while (separator[0] == delimiter || separator[0] == ' ')
			separator++;
		delim_list_str = separator;
	}
	return str_count;
}
