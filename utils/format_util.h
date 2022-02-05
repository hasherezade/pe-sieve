#pragma once

#include <windows.h>

#include <string>
#include <set>
#include <sstream>
#include <iomanip>

#include "strings_util.h"

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

		// Checks if the given string is in the given set
		bool is_in_list(std::string searched_string, std::set<std::string>& string_list, bool to_lower=true);

		size_t string_to_list(IN::std::string s, IN char _delim, OUT std::set<std::string>& elements_list, bool to_lower=true);

	};
};

