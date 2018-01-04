#pragma once

#include <Windows.h>

#include <pshpack4.h> // ensure 4 byte packing of the structures

typedef struct {
	DWORD pid;
	DWORD filter;
	bool imp_rec;
	bool no_dump;
	bool quiet;
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
