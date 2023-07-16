#pragma once

#include <iostream>
#include <pe_sieve_types.h>

namespace pesieve {

	void params_fields_to_JSON(pesieve::t_params& params, std::stringstream& outs, size_t level);
	void params_to_JSON(pesieve::t_params& params, std::stringstream& stream, size_t start_level);
};

