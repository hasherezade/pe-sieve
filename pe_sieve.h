#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"
#include "scanners/scan_report.h"
#include "report_formatter.h"

static char VERSION[] = "0.0.9.9.8";
static char URL[] = "https://github.com/hasherezade/pe-sieve";

std::string info();
std::string make_dir_name(const DWORD process_id);

ProcessScanReport* check_modules_in_process(const t_params args);
