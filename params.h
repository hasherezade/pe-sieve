#pragma once
#include <sstream>

#include "pe_sieve.h"
#include "params_info/pe_sieve_params_info.h"

#include <paramkit.h>

using namespace paramkit;
using namespace pesieve;

//scan options:
#define PARAM_PID "pid"
#define PARAM_SHELLCODE "shellc"
#define PARAM_OBFUSCATED "obfusc"
#define PARAM_THREADS "threads"
#define PARAM_DATA "data"
#define PARAM_IAT "iat"
#define PARAM_MODULES_IGNORE "mignore"
#define PARAM_REFLECTION "refl"
#define PARAM_DOTNET_POLICY "dnet"

//dump options:
#define PARAM_IMP_REC "imp"
#define PARAM_DUMP_MODE "dmode"
//output options:
#define PARAM_OUT_FILTER "ofilter"
#define PARAM_QUIET "quiet"
#define PARAM_JSON "json"
#define PARAM_JSON_LVL "jlvl"
#define PARAM_DIR "dir"
#define PARAM_MINIDUMP "minidmp"
#define PARAM_PATTERN "pattern"


bool alloc_strparam(PARAM_STRING& strparam, ULONG len)
{
	if (strparam.buffer != nullptr) { // already allocated
		return false;
	}
	strparam.buffer = (char*)calloc(len + 1, sizeof(char));
	if (strparam.buffer) {
		strparam.length = len;
		return true;
	}
	return false;
}

void free_strparam(PARAM_STRING& strparam)
{
	free(strparam.buffer);
	strparam.buffer = nullptr;
	strparam.length = 0;
}

class PEsieveParams : public Params
{
public:
	PEsieveParams(const std::string &version)
		: Params(version)
	{
		this->addParam(new IntParam(PARAM_PID, true));
		this->setInfo(PARAM_PID, "Set the PID of the target process.");

		EnumParam *enumParam = new EnumParam(PARAM_IMP_REC, "imprec_mode", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_IMP_REC, "Set in which mode the ImportTable should be recovered");
			for (size_t i = 0; i < PE_IMPREC_MODES_COUNT; i++) {
				t_imprec_mode mode = (t_imprec_mode)(i);
				enumParam->addEnumValue(mode, imprec_mode_to_id(mode), translate_imprec_mode(mode));
			}
		}

		enumParam = new EnumParam(PARAM_OUT_FILTER, "ofilter_id", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_OUT_FILTER, "Filter the dumped output.");
			for (size_t i = 0; i < OUT_FILTERS_COUNT; i++) {
				t_output_filter mode = (t_output_filter)(i);
				enumParam->addEnumValue(mode, translate_out_filter(mode));
			}
		}

		this->addParam(new StringListParam(PARAM_MODULES_IGNORE, false, PARAM_LIST_SEPARATOR));
		{
			std::stringstream ss1;
			ss1 << "Do not scan module/s with given name/s.";
			std::stringstream ss2;
			ss2 << INFO_SPACER << "Example: kernel32.dll" << PARAM_LIST_SEPARATOR << "user32.dll";
			this->setInfo(PARAM_MODULES_IGNORE, ss1.str(), ss2.str());
		}
		
		this->addParam(new BoolParam(PARAM_QUIET, false));
		this->setInfo(PARAM_QUIET, "Print only the summary. Do not log on stdout during the scan.");

		this->addParam(new BoolParam(PARAM_JSON, false));
		this->setInfo(PARAM_JSON, "Print the JSON report as the summary.");
		//
		//PARAM_JSON_LVL
		enumParam = new EnumParam(PARAM_JSON_LVL, "json_lvl", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_JSON_LVL, "Level of details of the JSON report.");
			for (size_t i = 0; i < JSON_LVL_COUNT; i++) {
				t_json_level mode = (t_json_level)(i);
				enumParam->addEnumValue(mode, translate_json_level(mode));
			}
		}

		this->addParam(new BoolParam(PARAM_MINIDUMP, false));
		this->setInfo(PARAM_MINIDUMP, "Create a minidump of the full suspicious process.");

		//PARAM_SHELLCODE
		enumParam = new EnumParam(PARAM_SHELLCODE, "shellc_mode", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_SHELLCODE, "Detect shellcode implants (by patterns or statistics). ");
			for (size_t i = 0; i < SHELLC_COUNT; i++) {
				t_shellc_mode mode = (t_shellc_mode)(i);
				enumParam->addEnumValue(mode, shellc_mode_mode_to_id(mode), translate_shellc_mode(mode));
			}
		}
		
		this->addParam(new StringParam(PARAM_PATTERN, false));
		this->setInfo(PARAM_PATTERN, "Set additional shellcode patterns (file in the SIG format).");

		//PARAM_OBFUSCATED
		enumParam = new EnumParam(PARAM_OBFUSCATED, "obfusc_mode", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_OBFUSCATED, "Detect encrypted content, and possible obfuscated shellcodes.");
			for (size_t i = 0; i < OBFUSC_COUNT; i++) {
				t_obfusc_mode mode = (t_obfusc_mode)(i);
				enumParam->addEnumValue(mode, obfusc_mode_mode_to_id(mode), translate_obfusc_mode(mode));
			}
		}

		//PARAM_THREADS
		this->addParam(new BoolParam(PARAM_THREADS, false));
		this->setInfo(PARAM_THREADS, "Scan threads' callstack. Detect shellcodes, incl. 'sleeping beacons'.");

		//PARAM_REFLECTION
		this->addParam(new BoolParam(PARAM_REFLECTION, false));
		this->setInfo(PARAM_REFLECTION, 
			"Make a process reflection before scan.", 
			std::string(INFO_SPACER) + "This allows i.e. to force-read inaccessible pages."
		);

		//PARAM_IAT
		enumParam = new EnumParam(PARAM_IAT, "iat_scan_mode", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_IAT, "Scan for IAT hooks.");
			for (size_t i = 0; i < PE_IATS_MODES_COUNT; i++) {
				t_iat_scan_mode mode = (t_iat_scan_mode)(i);
				enumParam->addEnumValue(mode, translate_iat_scan_mode(mode));
			}
		}

		//PARAM_DOTNET_POLICY
		enumParam = new EnumParam(PARAM_DOTNET_POLICY, "dotnet_policy", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_DOTNET_POLICY, "Set the policy for scanning managed processes (.NET).");
			for (size_t i = 0; i < PE_DNET_COUNT; i++) {
				t_dotnet_policy mode = (t_dotnet_policy)(i);
				enumParam->addEnumValue(mode, translate_dotnet_policy(mode));
			}
		}

		//PARAM_DATA
		enumParam = new EnumParam(PARAM_DATA, "data_scan_mode", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_DATA, "Set if non-executable pages should be scanned.");
			for (size_t i = 0; i < PE_DATA_COUNT; i++) {
				t_data_scan_mode mode = (t_data_scan_mode)(i);
				enumParam->addEnumValue(mode, translate_data_mode(mode));
			}
		}

		//PARAM_DUMP_MODE
		enumParam = new EnumParam(PARAM_DUMP_MODE, "dump_mode", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_DUMP_MODE, "Set in which mode the detected PE files should be dumped.");
			for (size_t i = 0; i < PE_DUMP_MODES_COUNT; i++) {
				peconv::t_pe_dump_mode mode = (peconv::t_pe_dump_mode)(i);
				enumParam->addEnumValue(mode, dump_mode_to_id(mode), translate_dump_mode(mode));
			}
		}

		//PARAM_DIR
		this->addParam(new StringParam(PARAM_DIR, false));
		this->setInfo(PARAM_DIR, "Set a root directory for the output (default: current directory).");

		//optional: group parameters
		std::string str_group = "5. output options";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_DIR, str_group);
		this->addParamToGroup(PARAM_JSON, str_group);
		this->addParamToGroup(PARAM_JSON_LVL, str_group);
		this->addParamToGroup(PARAM_OUT_FILTER, str_group);

		str_group = "1. scanner settings";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_QUIET, str_group);
		this->addParamToGroup(PARAM_REFLECTION, str_group);

		str_group = "3. scan options";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_DATA, str_group);
		this->addParamToGroup(PARAM_IAT, str_group);
		this->addParamToGroup(PARAM_SHELLCODE, str_group);
		this->addParamToGroup(PARAM_OBFUSCATED, str_group);
		this->addParamToGroup(PARAM_THREADS, str_group);
		this->addParamToGroup(PARAM_PATTERN, str_group);

		str_group = "4. dump options";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_MINIDUMP, str_group);
		this->addParamToGroup(PARAM_IMP_REC, str_group);
		this->addParamToGroup(PARAM_DUMP_MODE, str_group);

		str_group = "2. scan exclusions";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_DOTNET_POLICY, str_group);
		this->addParamToGroup(PARAM_MODULES_IGNORE, str_group);
	}

	bool fillStringParam(const std::string &paramId, PARAM_STRING &strparam)
	{
		StringParam* myStr = dynamic_cast<StringParam*>(this->getParam(paramId));
		if (!myStr || !myStr->isSet()) {
			return false;
		}
		std::string val = myStr->valToString();
		const size_t len = val.length();
		if (!len) {
			return false;
		}
		alloc_strparam(strparam, len);
		bool is_copied = false;
		if (strparam.buffer) {
			is_copied = copyCStr<StringParam>(paramId, strparam.buffer, strparam.length);
		}
		return is_copied;
	}

	void fillStruct(t_params &ps)
	{
		copyVal<IntParam>(PARAM_PID, ps.pid);
		copyVal<EnumParam>(PARAM_IMP_REC, ps.imprec_mode);
		copyVal<EnumParam>(PARAM_OUT_FILTER, ps.out_filter);

		fillStringParam(PARAM_MODULES_IGNORE, ps.modules_ignored);

		copyVal<BoolParam>(PARAM_QUIET, ps.quiet);
		copyVal<BoolParam>(PARAM_JSON, ps.json_output);

		copyVal<EnumParam>(PARAM_JSON_LVL, ps.json_lvl);

		copyVal<BoolParam>(PARAM_MINIDUMP, ps.minidump);
		copyVal<EnumParam>(PARAM_SHELLCODE, ps.shellcode);
		copyVal<EnumParam>(PARAM_OBFUSCATED, ps.obfuscated);
		copyVal<BoolParam>(PARAM_THREADS, ps.threads);
		copyVal<BoolParam>(PARAM_REFLECTION, ps.make_reflection);

		copyVal<EnumParam>(PARAM_IAT, ps.iat);
		copyVal<EnumParam>(PARAM_DOTNET_POLICY, ps.dotnet_policy);
		copyVal<EnumParam>(PARAM_DATA, ps.data);
		copyVal<EnumParam>(PARAM_DUMP_MODE, ps.dump_mode);

		copyCStr<StringParam>(PARAM_DIR, ps.output_dir, _countof(ps.output_dir));
		fillStringParam(PARAM_PATTERN, ps.pattern_file);
	}

	void printBanner()
	{
		char logo[] = "\
.______    _______           _______. __   ___________    ____  _______ \n\
|   _  \\  |   ____|         /       ||  | |   ____\\   \\  /   / |   ____|\n\
|  |_)  | |  |__    ______ |   (----`|  | |  |__   \\   \\/   /  |  |__   \n\
|   ___/  |   __|  |______| \\   \\    |  | |   __|   \\      /   |   __|  \n\
|  |      |  |____      .----)   |   |  | |  |____   \\    /    |  |____ \n\
| _|      |_______|     |_______/    |__| |_______|   \\__/     |_______|\n";

		char logo2[] = "\
  _        _______       _______      __   _______     __       _______ \n";
		char logo3[] = "\
________________________________________________________________________\n";
		paramkit::print_in_color(DARK_GREEN, logo);
		paramkit::print_in_color(DARK_RED, logo2);
		paramkit::print_in_color(DARK_RED, logo3);
		std::cout << "\n";
		std::cout << pesieve::info();
	}

};
