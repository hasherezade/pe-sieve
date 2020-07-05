#pragma once

#include <iostream>
#include <pe_sieve_types.h>

namespace pesieve {
	std::string translate_dump_mode(const DWORD dump_mode);
	std::string translate_out_filter(const pesieve::t_output_filter o_filter);
	std::string translate_modules_filter(DWORD m_filter);
	std::string translate_data_mode(const pesieve::t_data_scan_mode &mode);
	std::string translate_imprec_mode(const pesieve::t_imprec_mode imprec_mode);
	std::string translate_dotnet_policy(const pesieve::t_dotnet_policy &mode);
	std::string translate_iat_scan_mode(const pesieve::t_iat_scan_mode mode);

	pesieve::t_imprec_mode normalize_imprec_mode(size_t mode_id);
	pesieve::t_dump_mode normalize_dump_mode(size_t mode_id);
};


