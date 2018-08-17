#pragma once

#include <Windows.h>
#include <sstream>
#include <iomanip>

#define OUT_PADDED(stream, field_size, str) std::cout.fill(' '); stream << std::setw(field_size*2)  << ' ' << str;

char* get_file_name(char *full_path);

char* get_directory(IN char *full_path, OUT char *out_buf, IN const size_t out_buf_size);

char* get_subpath_ptr(char *modulePath, char* searchedPath);

std::string to_lowercase(std::string);

// Find given prefix in the string, and remove it if found. Case insensitive.
std::string strip_prefix(std::string path, std::string prefix);

//add escape characters to path separators
std::string escape_path_separators(std::string path);

//get system drive letter, i.e. "C:"
std::string get_system_drive();
