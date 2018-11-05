#pragma once

#include <iostream>
#include "pe_sieve.h"

std::string translate_dump_mode(const DWORD dump_mode);
std::string translate_out_filter(const t_output_filter o_filter);
std::string translate_modules_filter(DWORD m_filter);
