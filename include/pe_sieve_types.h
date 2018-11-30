#pragma once

#include <vector>
#include <Windows.h>

#include <pshpack4.h> // ensure 4 byte packing of the structures

typedef enum {
	OUT_FULL = 0,
	OUT_NO_DUMPS,
	OUT_NO_DIR,
	OUT_FILTERS_COUNT
} t_output_filter;

typedef struct {
	DWORD pid;
	DWORD modules_filter;
	bool imp_rec;
	bool quiet; // do not print log on the stdout
	t_output_filter out_filter;
	bool no_hooks; // don't scan for hooks
	bool shellcode; // detect shellcode implants
	DWORD dump_mode;
	bool json_output;
	char output_dir[MAX_PATH];
} t_params;

typedef struct {
	DWORD pid; // pid of the process that was scanned
	DWORD scanned; // number of all scanned modules
	DWORD suspicious;// general summary of suspicious
	DWORD replaced; // PE file replaced in memory (probably hollowed)
	DWORD detached; // cannot find the file corresponding to the module in memory
	DWORD hooked; // detected modifications in the code
	DWORD implanted; // the full PE was probably loaded manually
	DWORD skipped; // some of the modules must be skipped (i.e. dotNET managed code have different characteristics and this scan does not apply)
	DWORD errors; // errors prevented the scan
} t_report;

#include <poppack.h> //back to the previous structure packing
