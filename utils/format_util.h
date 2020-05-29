#pragma once

#include <windows.h>
#include <sstream>
#include <iomanip>

#define OUT_PADDED(stream, field_size, str) \
std::cout.fill(' '); \
if (field_size) stream << std::setw(field_size) << ' '; \
stream << str;

namespace pesieve {

	namespace util {

		/*
		Get hexadecimal or decimal number from a string. Hexadecimal numbers should be prefixed with "0x".
		*/
		long get_number(const char *buf);

		/*
		Checks if the buffer is a number (hexadecimal or decimal ). Hexadecimal numbers should be prefixed with "0x".
		*/
		bool is_number(const char* buf);

		std::string to_lowercase(std::string);

		// Checks if the given cstring is in the multi-SZ list
		bool is_in_list(const char *searched_string, const char *strings_list);

		// Converts a delimiter-separated list (i.e. "kernel32.dll,user32.dll,ntdll.dll") into multi-SZ string. Returns the count of the strings.
		size_t delim_list_to_multi_sz(IN const char* delim_list_str, IN const char delimiter, OUT char* buffer, IN const size_t buffer_max_chars);

	};
};

