#include "module_data.h"

#include "utils/util.h"
#include "utils/path_converter.h"

//---
bool ModuleData::convertPath()
{
	std::string my_path =  convert_to_win32_path(this->szModName);
	if (my_path.length() == 0) {
		return false;
	}
	// store the new path in the buffer:
	memset(this->szModName, 0, MAX_PATH);

	// store the new path in the buffer:
	size_t max_len = my_path.length();
	if (max_len > MAX_PATH) max_len = MAX_PATH;

	memcpy(this->szModName, my_path.c_str(), max_len);
	return true;
}

bool ModuleData::loadOriginal()
{
	if (!GetModuleFileNameExA(processHandle, this->moduleHandle, szModName, MAX_PATH)) {
		is_module_named = false;
		const char unnamed[] = "unnamed";
		memcpy(szModName, unnamed, sizeof(unnamed));
	}
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (original_module != nullptr) {
		return true;
	}
	// try to convert path:
	if (!convertPath()) {
		return false;
	}
	std::cout << "[OK] Converted the path: " << szModName << std::endl;
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	return true;
}

bool ModuleData::reloadWow64()
{
	bool is_converted = convert_to_wow64_path(szModName);
	if (!is_converted) return false;

	//reload it and check again...
	peconv::free_pe_buffer(original_module, original_size);
	original_module = peconv::load_pe_module(szModName, original_size, false, false);
	if (!original_module) {
		return false;
	}
	return true;
}
