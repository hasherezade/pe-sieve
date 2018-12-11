#include "util.h"

#include <sstream>
#include <iomanip>
#include <algorithm>

char* get_file_name(char *full_path)
{
	if (!full_path) return nullptr;

	size_t len = strlen(full_path);
	if (len < 2) {
		return full_path;
	}
	for (size_t i = len - 2; i > 0; i--) {
		if (full_path[i] == '\\' || full_path[i] == '/') {
			return full_path + (i + 1);
		}
	}
	return full_path;
}

char* get_directory(IN char *full_path, OUT char *out_buf, IN const size_t out_buf_size)
{
	if (!full_path) return nullptr;

	memset(out_buf, 0, out_buf_size);
	memcpy(out_buf, full_path, out_buf_size);

	char *name_ptr = get_file_name(out_buf);
	if (name_ptr != nullptr) {
		*name_ptr = '\0'; //cut it
	}
	return out_buf;
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

bool dir_exists(const char* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool create_dir_recursively(std::string path)
{
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
