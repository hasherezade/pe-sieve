#pragma once
#include <windows.h>
#include <string>

bool make_minidump(DWORD pid, std::string out_file);
