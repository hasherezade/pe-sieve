#pragma once

#include <iostream>

std::string convert_to_win32_path(std::string path);

char get_drive_letter(std::string device_path);

std::string device_path_to_win32_path(std::string full_path);
