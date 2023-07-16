#include "params_dump.h"

#include "../utils/format_util.h"

void pesieve::params_fields_to_JSON(pesieve::t_params& params, std::stringstream& outs, size_t level)
{
	if (params.modules_ignored.length && params.modules_ignored.buffer) {
		OUT_PADDED(outs, level, "\"modules_ignored\" : ");
		outs << "\"" << params.modules_ignored.buffer << "\"" << ",\n";
	}
	if (params.data) {
		OUT_PADDED(outs, level, "\"data\" : ");
		outs << std::dec << params.data << ",\n";
	}
	if (params.dotnet_policy) {
		OUT_PADDED(outs, level, "\"dotnet_policy\" : ");
		outs << std::dec << params.dotnet_policy << ",\n";
	}

	if (params.make_reflection) {
		OUT_PADDED(outs, level, "\"use_reflection\" : ");
		outs << std::dec << params.make_reflection << ",\n";
	}
	if (params.use_cache) {
		OUT_PADDED(outs, level, "\"use_cache\" : ");
		outs << std::dec << params.use_cache << ",\n";
	}
	if (params.out_filter) {
		OUT_PADDED(outs, level, "\"out_filter\" : ");
		outs << std::dec << params.out_filter << ",\n";
	}
	if (params.imprec_mode) {
		OUT_PADDED(outs, level, "\"imprec_mode\" : ");
		outs << std::dec << params.imprec_mode << ",\n";
	}

	OUT_PADDED(outs, level, "\"hooks\" : ");
	outs << std::dec << (params.no_hooks ? 0 : 1) << ",\n";

	OUT_PADDED(outs, level, "\"iat\" : ");
	outs << std::dec << params.iat << ",\n";

	OUT_PADDED(outs, level, "\"threads\" : ");
	outs << std::dec << params.threads << ",\n";

	OUT_PADDED(outs, level, "\"shellcode\" : ");
	outs << std::dec << params.shellcode << ",\n";

	OUT_PADDED(outs, level, "\"obfuscated\" : ");
	outs << std::dec << params.obfuscated << "\n";
}


void pesieve::params_to_JSON(pesieve::t_params& params, std::stringstream& stream, size_t level)
{
	OUT_PADDED(stream, level, "\"pesieve_params\" : {\n");
	params_fields_to_JSON(params, stream, level + 1);
	OUT_PADDED(stream, level, "}");
}
