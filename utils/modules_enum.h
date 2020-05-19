#pragma once

#include <windows.h>
#include <stdexcept>

size_t enum_modules(IN HANDLE hProcess, IN OUT HMODULE hMods[], IN const DWORD hModsMax, IN DWORD filters); //throws exceptions

