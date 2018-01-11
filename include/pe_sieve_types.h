#pragma once

#include <vector>
#include <Windows.h>

#include <pshpack4.h> // ensure 4 byte packing of the structures

typedef enum {
	OUT_FULL = 0,
	OUT_NO_DUMPS = 1,
	OUT_NO_DIR = 2
} t_output_filter;

typedef struct {
	DWORD pid;
	DWORD modules_filter;
	bool imp_rec;
	bool quiet; // do not print log on the stdout
	t_output_filter out_filter;
	bool no_hooks; // don't scan for hooks
	bool json_output;
} t_params;

typedef struct {
	DWORD pid;
	DWORD scanned;
	DWORD replaced;
	DWORD hooked;
	DWORD suspicious;
	DWORD errors;
} t_report;

#include <poppack.h> //back to the previous structure packing
