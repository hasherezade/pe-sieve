#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_api.h"

static char VERSION[] = "0.0.9.1";

t_report check_modules_in_process(const t_params args);
std::string report_to_string(const t_report report);

std::string make_dir_name(const DWORD process_id);
