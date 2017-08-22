#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"

// Map virtual image of PE to into raw:
BYTE* pe_virtual_to_raw(const BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &out_size);
