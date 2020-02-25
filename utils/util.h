#pragma once

#include <Windows.h>
#include <sstream>
#include <iomanip>

#define OUT_PADDED(stream, field_size, str) \
std::cout.fill(' '); \
if (field_size) stream << std::setw(field_size) << ' '; \
stream << str;

/*
Get hexadecimal or decimal number from a string. Hexadecimal numbers should be prefixed with "0x".
*/
long get_number(const char *buf);

/*
Checks if the buffer is a number (hexadecimal or decimal ). Hexadecimal numbers should be prefixed with "0x".
*/
bool is_number(const char* buf);

char* get_subpath_ptr(char *modulePath, char* searchedPath);

std::string to_lowercase(std::string);

// Find given prefix in the string, and remove it if found. Case insensitive.
std::string strip_prefix(std::string path, std::string prefix);

//add escape characters to path separators
std::string escape_path_separators(std::string path);

//get system drive letter, i.e. "C:"
std::string get_system_drive();

bool dir_exists(const char* path);

bool create_dir_recursively(const std::string& path);

template <typename XCHAR>
const XCHAR * get_plain_name(const XCHAR * szFilePath)
{
	const XCHAR * plain_name = szFilePath;

	while (szFilePath[0] != 0)
	{
		if (szFilePath[0] == '\\' || szFilePath[0] == '/')
			plain_name = szFilePath + 1;
		szFilePath++;
	}

	return plain_name;
}

// Checks if the given cstring is in the multi-SZ list
bool is_in_list(const char *searched_string, const char *strings_list);

// Converts a delimiter-separated list (i.e. "kernel32.dll,user32.dll,ntdll.dll") into multi-SZ string. Returns the count of the strings.
size_t delim_list_to_multi_sz(IN const char* delim_list_str, IN const char delimiter, OUT char* buffer, OUT size_t buffer_max_chars);
