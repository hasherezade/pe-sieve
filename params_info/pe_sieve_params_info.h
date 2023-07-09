#pragma once

#include <iostream>
#include <pe_sieve_types.h>

namespace pesieve {
	std::string translate_dump_mode(const DWORD dump_mode);
	std::string translate_out_filter(const pesieve::t_output_filter o_filter);
	std::string translate_data_mode(const pesieve::t_data_scan_mode &mode);
	std::string translate_imprec_mode(const pesieve::t_imprec_mode imprec_mode);
	std::string translate_dotnet_policy(const pesieve::t_dotnet_policy &mode);
	std::string translate_iat_scan_mode(const pesieve::t_iat_scan_mode mode);
	std::string translate_json_level(const pesieve::t_json_level &mode);
	std::string translate_shellc_mode(const pesieve::t_shellc_mode& mode);
	std::string shellc_mode_mode_to_id(const pesieve::t_shellc_mode& mode);

	std::string translate_obfusc_mode(const pesieve::t_obfusc_mode& mode);
	std::string obfusc_mode_mode_to_id(const pesieve::t_obfusc_mode& mode);

	std::string dump_mode_to_id(const DWORD dump_mode);
	std::string imprec_mode_to_id(const pesieve::t_imprec_mode imprec_mode);
};

