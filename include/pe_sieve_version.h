#pragma once

#include <windows.h>
#include <pe_sieve_ver_short.h>

#ifdef __cplusplus
namespace pesieve {
#endif
	const DWORD PESIEVE_VERSION_ID = MAKELONG(MAKEWORD(PESIEVE_PATCH_VERSION, PESIEVE_MICRO_VERSION), MAKEWORD(PESIEVE_MINOR_VERSION, PESIEVE_MAJOR_VERSION));
	const char PESIEVE_URL[] = "https://github.com/hasherezade/pe-sieve";

#ifdef __cplusplus
};
#endif
