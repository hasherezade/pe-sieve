#pragma once
#include <Windows.h>
#include <string>

bool make_minidump(DWORD pid, std::string out_file);
