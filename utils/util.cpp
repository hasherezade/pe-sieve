#include "util.h"

#include <sstream>
#include <iomanip>
#include <algorithm>

char g_System32Path[MAX_PATH] = { 0 }; //= "C:\\Windows\\system32";
char g_Syswow64Path[MAX_PATH] = { 0 }; //= "C:\\Windows\\SysWOW64";

void init_syspaths()
{
    if (!g_System32Path[0]) {
        memset(g_System32Path, 0, MAX_PATH);
        GetWindowsDirectory(g_System32Path, MAX_PATH);
        lstrcatA(g_System32Path, "\\system32");
    }
    if (!g_Syswow64Path[0]) {
        memset(g_Syswow64Path, 0, MAX_PATH);
        GetWindowsDirectory(g_Syswow64Path, MAX_PATH);
        lstrcatA(g_Syswow64Path, "\\SysWOW64");
    }
}

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

bool is_system_dll(char *szModName, BOOL isWow64)
{
	init_syspaths();
	if (get_subpath_ptr(szModName, g_System32Path)) {
		return true;
	}
	return false;
}

bool convert_to_wow64_path(char *szModName)
{
	init_syspaths();
	size_t sysPathLen = strlen(g_Syswow64Path);
	if (!get_subpath_ptr(szModName, g_System32Path)) {
		return false;
	}
	memcpy(szModName, g_Syswow64Path, sysPathLen);
	return true;
}

std::string to_lowercase(std::string str)
{
	std::transform(str.begin(), str.end(), str.begin(), tolower);
	return str;
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
