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
	const size_t min_length = 1; //tolerate number with at least 1 character
	if (len > hex_pattern_len) {
		if (is_cstr_equal(my_buf, hex_pattern, hex_pattern_len)) {
			if (!is_hex(my_buf + hex_pattern_len, min_length)) return 0;

			std::stringstream ss;
			ss << std::hex << my_buf;
			ss >> out;
			return out;
		}
	}
	if (!is_dec(my_buf, min_length)) return 0;

	std::stringstream ss;
	ss << std::dec << my_buf;
	ss >> out;
	return out;
}

bool pesieve::util::is_number(const char* my_buf)
{
	const char hex_pattern[] = "0x";
	size_t hex_pattern_len = strlen(hex_pattern);

	const size_t len = strlen(my_buf);
	if (len == 0) return false;

	if (len > hex_pattern_len) {
		if (is_cstr_equal(my_buf, hex_pattern, hex_pattern_len)) {
			if (!is_hex(my_buf + hex_pattern_len, len - hex_pattern_len)) return false;

			return true;
		}
	}
	if (!is_dec(my_buf, len)) return false;
	return true;
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

size_t pesieve::util::delim_list_to_multi_sz(IN const std::string & input, IN const char delimiter, OUT std::string & output)
{
	char * target_begin;
	char * source_end;
	char * source;
	char * target;
	size_t length;

	// Copy the source into the target; we will work on top of the target's buffer
	output = input;

	// Append two chars to make sure we have enough space for two zeros.
	// Don't count them into length
	length = output.size();
	output.append(2, delimiter);

	// Prepare the pointer range
	target_begin = target = source = (char *)(output.c_str());
	source_end = source + length;

	// Parse the input string. Separator and any spaces following behind it are skipped.
	while(source < source_end)
	{
		// Did we find the delimiter?
		if(source[0] == delimiter)
		{
			// Skip the source delimiter and all. Put zero to the target
			while(source[0] == delimiter || source[0] == ' ')
				source++;
			*target++ = 0;
			continue;
		}

		// Simply copy the char
		*target++ = *source++;
	}

	// Append two zeros, making it multi-sz
	*target++ = 0;
	*target++ = 0;

	// Return length of the target
	return (target - target_begin);
}

