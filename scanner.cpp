#include "scanner.h"

#include <sstream>
#include <iomanip>

char* get_file_name(char *full_path)
{
	size_t len = strlen(full_path);
	for (size_t i = len - 2; i >= 0; i--) {
		if (full_path[i] == '\\' || full_path[i] == '/') {
			return full_path + (i + 1);
		}
	}
	return nullptr;
}

std::string make_module_path(MODULEENTRY32 &module_entry, std::string directory)
{
	char* fname = get_file_name(module_entry.szExePath);
	std::stringstream stream;
	if (directory.length() > 0) {
		stream << directory;
		stream << "\\";
	}
	stream << std::hex << (ULONGLONG)module_entry.modBaseAddr;
	if (fname != nullptr) {
		stream << "." << fname;
	} else {
		stream << ".dll";
	}
	return stream.str();
}