#pragma once

#include <iostream>

//converts path in format: \SystemRoot\... to format: C:\...
std::string convert_to_win32_path(std::string path);

char get_drive_letter(std::string device_path);

//converts path in format i.e.: \Device\HarddiskVolume2\... to format: C:\...
std::string device_path_to_win32_path(std::string full_path);
