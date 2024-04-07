#include "path_util.h"

#include "format_util.h"

char* pesieve::util::get_subpath_ptr(char *modulePath, char* searchedPath)
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

std::string pesieve::util::escape_path_separators(std::string path)
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

std::string pesieve::util::get_system_drive()
{
	char buf[MAX_PATH] = { 0 };
	if (!GetWindowsDirectoryA(buf, MAX_PATH)) {
		return "";
	}
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

bool pesieve::util::dir_exists(const char* szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool pesieve::util::create_dir_recursively(const std::string& in_path)
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

std::string pesieve::util::strip_prefix(std::string path, std::string prefix)
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

