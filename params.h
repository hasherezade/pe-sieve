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

class PEsieveParams : public Params
{
public:
	PEsieveParams(const std::string &version)
		: Params(version)
	{
		this->addParam(new IntParam(PARAM_PID, true));
		this->setInfo(PARAM_PID, "Set the PID of the target process.");//\n\t(decimal, or hexadecimal with '0x' prefix)");

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

		this->addParam(new StringParam(PARAM_MODULES_IGNORE, false));
		{
			std::stringstream ss;
			ss << "Do not scan module/s with given name/s (separated by '" << PARAM_LIST_SEPARATOR << "').\n"
				<< "\t  Example: kernel32.dll" << PARAM_LIST_SEPARATOR << "user32.dll";
			this->setInfo(PARAM_MODULES_IGNORE, ss.str());
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
		this->addParam(new BoolParam(PARAM_SHELLCODE, false));
		this->setInfo(PARAM_SHELLCODE, "Detect shellcode implants. (By default it detects PE only).");

		//PARAM_REFLECTION
		this->addParam(new BoolParam(PARAM_REFLECTION, false));
		this->setInfo(PARAM_REFLECTION, "Make a process reflection before scan.\n\t   This allows i.e. to force-read inaccessible pages.");

		//PARAM_IAT
		enumParam = new EnumParam(PARAM_IAT, "scan_mode", false);
		if (enumParam) {
			this->addParam(enumParam);
			this->setInfo(PARAM_IAT, "Level of details of the JSON report.");
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
		std::string str_group = "output options";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_DIR, str_group);
		this->addParamToGroup(PARAM_JSON, str_group);
		this->addParamToGroup(PARAM_JSON_LVL, str_group);
		this->addParamToGroup(PARAM_OUT_FILTER, str_group);

		str_group = "scanner settings";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_QUIET, str_group);
		this->addParamToGroup(PARAM_REFLECTION, str_group);

		str_group = "scan options";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_DATA, str_group);
		this->addParamToGroup(PARAM_IAT, str_group);
		this->addParamToGroup(PARAM_SHELLCODE, str_group);

		str_group = "dump options";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_MINIDUMP, str_group);
		this->addParamToGroup(PARAM_IMP_REC, str_group);
		this->addParamToGroup(PARAM_DUMP_MODE, str_group);

		str_group = "scan exclusions";
		this->addGroup(new ParamGroup(str_group));
		this->addParamToGroup(PARAM_DOTNET_POLICY, str_group);
		this->addParamToGroup(PARAM_MODULES_IGNORE, str_group);
	}

	void fillStruct(t_params &ps)
	{
		IntParam *intParam = dynamic_cast<IntParam*>(this->getParam(PARAM_PID));
		if (intParam) ps.pid = intParam->value;

		EnumParam* mEnum = dynamic_cast<EnumParam*>(this->getParam(PARAM_IMP_REC));
		if (mEnum && mEnum->isSet()) {
			ps.imprec_mode = (pesieve::t_imprec_mode)mEnum->value;
		}

		//PARAM_OUT_FILTER
		mEnum = dynamic_cast<EnumParam*>(this->getParam(PARAM_OUT_FILTER));
		if (mEnum && mEnum->isSet()) {
			ps.out_filter = (pesieve::t_output_filter)mEnum->value;
		}

		StringParam* mStr = dynamic_cast<StringParam*>(this->getParam(PARAM_MODULES_IGNORE));
		if (mStr) {
			mStr->copyToCStr(ps.modules_ignored, sizeof(ps.modules_ignored));
		}

		///PARAM_QUIET
		BoolParam* mBool = dynamic_cast<BoolParam*>(this->getParam(PARAM_QUIET));
		if (mBool && mBool->isSet()) {
			ps.quiet = mBool->value;
		}

		//PARAM_JSON
		mBool = dynamic_cast<BoolParam*>(this->getParam(PARAM_JSON));
		if (mBool && mBool->isSet()) {
			ps.json_output = mBool->value;
		}

		// PARAM_JSON_LVL
		mEnum = dynamic_cast<EnumParam*>(this->getParam(PARAM_JSON_LVL));
		if (mEnum && mEnum->isSet()) {
			ps.json_lvl = (pesieve::t_json_level)mEnum->value;
		}

		// PARAM_MINIDUMP
		mBool = dynamic_cast<BoolParam*>(this->getParam(PARAM_MINIDUMP));
		if (mBool && mBool->isSet()) {
			ps.minidump = mBool->value;
		}

		mBool = dynamic_cast<BoolParam*>(this->getParam(PARAM_SHELLCODE));
		if (mBool && mBool->isSet()) {
			ps.shellcode = mBool->value;
		}

		mBool = dynamic_cast<BoolParam*>(this->getParam(PARAM_REFLECTION));
		if (mBool && mBool->isSet()) {
			ps.make_reflection = mBool->value;
		}

		//PARAM_IAT
		mEnum = dynamic_cast<EnumParam*>(this->getParam(PARAM_IAT));
		if (mEnum && mEnum->isSet()) {
			ps.iat = (pesieve::t_iat_scan_mode)mEnum->value;
		}

		//PARAM_DOTNET_POLICY
		mEnum = dynamic_cast<EnumParam*>(this->getParam(PARAM_DOTNET_POLICY));
		if (mEnum && mEnum->isSet()) {
			ps.dotnet_policy = (pesieve::t_dotnet_policy)mEnum->value;
		}

		//PARAM_DATA
		mEnum = dynamic_cast<EnumParam*>(this->getParam(PARAM_DATA));
		if (mEnum && mEnum->isSet()) {
			ps.data = (pesieve::t_data_scan_mode)mEnum->value;
		}

		//PARAM_DUMP_MODE
		mEnum = dynamic_cast<EnumParam*>(this->getParam(PARAM_DUMP_MODE));
		if (mEnum && mEnum->isSet()) {
			ps.dump_mode = (pesieve::t_dump_mode)mEnum->value;
		}

		mStr = dynamic_cast<StringParam*>(this->getParam(PARAM_DIR));
		if (mStr) {
			mStr->copyToCStr(ps.output_dir, sizeof(ps.output_dir));
		}
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
		paramkit::print_in_color(2, logo);
		paramkit::print_in_color(4, logo2);
		paramkit::print_in_color(4, logo3);
		std::cout << "\n";
		std::cout << pesieve::info();
	}

};
