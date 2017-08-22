#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size);
