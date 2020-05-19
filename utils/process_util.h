#pragma once

#include <windows.h>

BOOL is_process_wow64(IN HANDLE processHandle, OUT BOOL* isProcWow64);
BOOL wow64_disable_fs_redirection(OUT PVOID* OldValue);
BOOL wow64_revert_fs_redirection(IN PVOID  OldValue);
