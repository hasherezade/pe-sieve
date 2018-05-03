#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"
#include "scanners/scan_report.h"
#include "report_formatter.h"

static char PESIEVE_VERSION[] = "0.1";
static DWORD PESIEVE_VERSION_ID = 0x00010000; // 00 01 00 00
static char PESIEVE_URL[] = "https://github.com/hasherezade/pe-sieve";

std::string info();
ProcessScanReport* check_modules_in_process(const t_params args);
