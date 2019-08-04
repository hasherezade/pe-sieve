#pragma once

#include <windows.h>
#include <iostream>
#include <stdexcept>

#include "pe_sieve_types.h"
#include "scanners/scan_report.h"
#include "postprocessors/report_formatter.h"

static char PESIEVE_VERSION[] = "0.2.1.4";
static DWORD PESIEVE_VERSION_ID = 0x00020104; // 00 02 01 04
static char PESIEVE_URL[] = "https://github.com/hasherezade/pe-sieve";

std::string info();
ProcessScanReport* scan_process(const pesieve::t_params args);
