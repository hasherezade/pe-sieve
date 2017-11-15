#pragma once
#include <Windows.h>
#include <TlHelp32.h>

#include "scanner_status.h"

t_scan_status is_module_hooked(HANDLE processHandle, MODULEENTRY32 &module_entry, BYTE* original_module, size_t module_size, char* directory);
