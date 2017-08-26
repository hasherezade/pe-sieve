#pragma once

#include "scanner_status.h"
#include "remote_pe_reader.h"

t_scan_status is_module_hooked(HANDLE processHandle, MODULEENTRY32 &module_entry, BYTE* original_module, size_t module_size, char* directory);
