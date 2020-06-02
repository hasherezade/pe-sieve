#pragma once

#include <windows.h>
#include <sstream>
#include <iomanip>

namespace pesieve {
	namespace util{

		char* get_subpath_ptr(char *modulePath, char* searchedPath);

		// Add escape characters to path separators
		std::string escape_path_separators(std::string path);

		// Get system drive letter, i.e. "C:"
		std::string get_system_drive();

		bool dir_exists(const char* path);

		bool create_dir_recursively(const std::string& path);

		// Find given prefix in the string, and remove it if found. Case insensitive.
		std::string strip_prefix(std::string path, std::string prefix);
	};
};
