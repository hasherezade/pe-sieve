#pragma once

#include <Windows.h>

BOOL is_process_wow64(IN HANDLE processHandle, OUT BOOL* isProcWow64);
