#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_hdrs_helper.h"

// Map virtual image of PE to into raw. If rebuffer is set, the input buffer is not modified.
BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &out_size, bool rebuffer=false);
