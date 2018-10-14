#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"
#include "scanners/scan_report.h"
#include "report_formatter.h"

static char PESIEVE_VERSION[] = "0.1.4.5";
static DWORD PESIEVE_VERSION_ID = 0x00010405; // 00 01 04 05
static char PESIEVE_URL[] = "https://github.com/hasherezade/pe-sieve";

std::string info();
ProcessScanReport* check_modules_in_process(const t_params args);
