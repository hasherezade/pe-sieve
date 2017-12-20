#pragma once

#include <Windows.h>
#include <sstream>

char* get_file_name(char *full_path);

std::string make_module_path(ULONGLONG modBaseAddr, char* szExePath,  std::string directory);
