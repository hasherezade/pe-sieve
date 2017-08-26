#pragma once

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

extern FILE* g_LogFile;

bool make_log_file(const char *filename);
void log_module_info(MODULEENTRY32 &module_entry);
bool close_log_file();

