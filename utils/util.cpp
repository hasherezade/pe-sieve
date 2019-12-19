#include "util.h"

#include <sstream>
#include <iomanip>
#include <algorithm>

bool is_hex(const char *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (buf[i] >= '0' && buf[i] <= '9') continue;
		if (buf[i] >= 'A' && buf[i] <= 'F') continue;
		if (buf[i] >= 'a' && buf[i] <= 'f') continue;
		return false;
	}
	return true;
}

bool is_dec(const char *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		if (buf[i] >= '0' && buf[i] <= '9') continue;
		return false;
	}
	return true;
}

long get_number(const char *my_buf)
{
	const char hex_pattern[] = "0x";
	size_t hex_pattern_len = strlen(hex_pattern);

	const size_t len = strlen(my_buf);
	if (len == 0) return 0;

	long out = 0;
	const size_t min_length = 1; //tolerate number with at least 1 character is fine
	if (len > hex_pattern_len) {
		if (strncmp(my_buf, hex_pattern, hex_pattern_len) == 0) {
			if (!is_hex(my_buf + hex_pattern_len, min_length)) return 0;

			out = std::stoul(my_buf, nullptr, 16);
			return out;
		}
	}
	if (!is_dec(my_buf, min_length)) return 0;

	out = std::stoul(my_buf, nullptr, 10);
	return out;
}

bool is_number(const char* my_buf)
{
	const char hex_pattern[] = "0x";
	size_t hex_pattern_len = strlen(hex_pattern);

	const size_t len = strlen(my_buf);
	if (len == 0) return false;

	if (len > hex_pattern_len) {
		if (strncmp(my_buf, hex_pattern, hex_pattern_len) == 0) {
			if (!is_hex(my_buf + hex_pattern_len, len - hex_pattern_len)) return false;

			return true;
		}
	}
	if (!is_dec(my_buf, len)) return false;
	return true;
}

char* get_subpath_ptr(char *modulePath, char* searchedPath)
{
	if (modulePath == nullptr || searchedPath == nullptr) {
		return nullptr;
	}
	size_t modNameLen = strlen(modulePath);
	size_t sysPathLen = strlen(searchedPath);
	size_t i = 0;
	for (; i < modNameLen && i < sysPathLen; i++) {
		char c1 = tolower(modulePath[i]);
		char c2 = tolower(searchedPath[i]);
		if (c1 == '/') c1 = '\\'; //normalize
		if (c1 != c2) {
			break;
		}
	}
	if (i == sysPathLen) {
		return modulePath + i;
	}
	return nullptr;
}

std::string to_lowercase(std::string str)
{
	std::transform(str.begin(), str.end(), str.begin(), tolower);
	return str;
}

std::string strip_prefix(std::string path, std::string prefix)
{
	const size_t prefix_len = prefix.length();
	if (prefix_len == 0) {
		return path;
	}
	// case insensitive:
	std::string my_path = to_lowercase(path);
	prefix = to_lowercase(prefix);

	size_t found_index = my_path.find(prefix);
	if (found_index != std::string::npos
		&& found_index == 0) //the found string must be at the beginning
	{
		path.erase(found_index, prefix_len);
	}
	return path;
}

std::string escape_path_separators(std::string path)
{
	size_t pos = std::string::npos;
	size_t prev = 0;
	const char to_escape = '\\';
	const std::string escaped = "\\\\";
	do
	{
		pos = path.find(to_escape, prev);
		if (pos == std::string::npos) break;

		path.replace(pos, 1, escaped);
		prev = pos + escaped.length();

	} while (pos < path.length() && prev < path.length());

	return path;
}

std::string get_system_drive()
{
	char buf[MAX_PATH];
	GetWindowsDirectory(buf, MAX_PATH);
	buf[2] = '\0'; // cut after the drive letter
	return std::string(buf);
}

std::string get_full_path(const char* szPath)
{
	char out_buf[MAX_PATH] = { 0 };
	if (GetFullPathNameA(szPath, MAX_PATH, out_buf, nullptr) == 0) {
		return "";
	}
	return out_buf;
}

bool dir_exists(const char* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool create_dir_recursively(const std::string& in_path)
{
	std::string path = get_full_path(in_path.c_str());
	if (path.length() == 0) path = in_path;

	if (dir_exists(path.c_str())) {
		return true;
	}
	size_t pos = 0;
	do
	{
		pos = path.find_first_of("\\/", pos + 1);
		if (CreateDirectoryA(path.substr(0, pos).c_str(), NULL) == FALSE) {
			if (GetLastError() != ERROR_ALREADY_EXISTS) {
				return false;
			}
		}
	} while (pos != std::string::npos);
	return true;
}
