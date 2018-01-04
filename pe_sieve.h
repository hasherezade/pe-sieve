#pragma once

#include <windows.h>
#include <iostream>

#include "pe_sieve_types.h"

static char VERSION[] = "0.0.9.2";
static char URL[] = "https://github.com/hasherezade/pe-sieve";

std::string info();
std::string make_dir_name(const DWORD process_id);

t_report check_modules_in_process(const t_params args);
std::string report_to_string(const t_report report);

