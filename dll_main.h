#pragma once

#include <windows.h>
#include "pe_sieve_api.h"

extern "C" {
	void __declspec(dllexport) __stdcall help(void);
	t_report __declspec(dllexport) __stdcall scan(t_params args);
};
