#include "tinylogger.h"

FILE* g_LogFile = NULL;

bool make_log_file(const char *filename)
{
	g_LogFile = fopen(filename, "w");
	if (!g_LogFile) {
		printf("[ERROR] Cannot open log file!\n");
		return false;
	}
	return true;
}

void log_module_info(MODULEENTRY32 &module_entry)
{
	BYTE* mod_end = module_entry.modBaseAddr + module_entry.modBaseSize;
	if (g_LogFile == NULL) {
		printf("%p,%p,%s\n", module_entry.modBaseAddr, mod_end, module_entry.szModule);
		return;
	}
	fprintf(g_LogFile, "%p,%p,%s\n", module_entry.modBaseAddr, mod_end, module_entry.szModule);
	fflush(g_LogFile);
}

bool close_log_file()
{
	if (g_LogFile == NULL) return false;
	fclose(g_LogFile);
	g_LogFile = NULL;
	return true;
}