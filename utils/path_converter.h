#pragma once

#include <iostream>

namespace pesieve {

	namespace util {

		//convert from System32 path to the WoW64 equivalent:
		bool convert_to_wow64_path(char *szModName);

		//converts path in format: \SystemRoot\... to format: C:\...
		std::string convert_to_win32_path(const std::string &path);

		//converts path in format i.e.: \Device\HarddiskVolume2\... to format: C:\...
		std::string device_path_to_win32_path(const std::string &full_path);

		std::string expand_path(std::string path);

	};
};

