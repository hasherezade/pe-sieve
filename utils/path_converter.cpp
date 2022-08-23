#include "path_converter.h"

#include <windows.h>

#include "ntddk.h"
#pragma comment(lib, "Ntdll.lib")

#include <shlwapi.h>
#pragma comment (lib, "shlwapi.lib")

#include <iostream>
#include <string>
#include <locale>
#include <codecvt>

#include "path_util.h"

#define LONG_PATH_PREFIX "\\\\?\\"
#define GLOBALROOT_NAME "GLOBALROOT"

char g_System32Path[MAX_PATH] = { 0 }; //= "C:\\Windows\\system32";
char g_Syswow64Path[MAX_PATH] = { 0 }; //= "C:\\Windows\\SysWOW64";

namespace pesieve {
	namespace util {

		void init_syspaths()
		{
			if (!g_System32Path[0]) {
				memset(g_System32Path, 0, MAX_PATH);
				ExpandEnvironmentStringsA("%SystemRoot%\\system32", g_System32Path, MAX_PATH);
			}
			if (!g_Syswow64Path[0]) {
				memset(g_Syswow64Path, 0, MAX_PATH);
				ExpandEnvironmentStringsA("%SystemRoot%\\SysWoW64", g_Syswow64Path, MAX_PATH);
			}
		}

		HANDLE nt_create_file(PCWSTR filePath)
		{
			HANDLE hFile;
			OBJECT_ATTRIBUTES objAttribs = { 0 };

			UNICODE_STRING unicodeString;
			RtlInitUnicodeString(&unicodeString, filePath);

			InitializeObjectAttributes(&objAttribs, &unicodeString, OBJ_CASE_INSENSITIVE, NULL, NULL);

			const int allocSize = 2048;
			LARGE_INTEGER largeInteger;
			largeInteger.QuadPart = allocSize;

			IO_STATUS_BLOCK ioStatusBlock = { 0 };
			NTSTATUS status = NtCreateFile(&hFile,
				STANDARD_RIGHTS_READ,
				&objAttribs,
				&ioStatusBlock,
				&largeInteger,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				FILE_NON_DIRECTORY_FILE,
				NULL,
				NULL
			);
			if (status != STATUS_SUCCESS) {
				std::wcerr << "Cannot open file: " << filePath << ". Error: " << std::hex << status << std::endl;
				return nullptr;
			}
			return hFile;
		}

		std::string nt_retrieve_file_path(HANDLE hFile)
		{
			IO_STATUS_BLOCK status_block = { 0 };

			struct MY_FILE_NAME_INFORMATION {
				ULONG FileNameLength;
				WCHAR FileName[MAX_PATH];
			} name_info;

			memset(&name_info, 0, sizeof(MY_FILE_NAME_INFORMATION));

			NTSTATUS status = ZwQueryInformationFile(hFile, &status_block, &name_info, sizeof(MY_FILE_NAME_INFORMATION), FileNameInformation);
			if (status != STATUS_SUCCESS) {
				return "";
			}
			std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
			std::string my_string = converter.to_bytes(name_info.FileName);

			my_string = get_system_drive() + my_string;
			return my_string;
		}

		bool is_relative(const char *path, size_t path_len)
		{
			if (path_len < 2) {
				return true;
			}
			// i.e. "c:\"
			if (path[1] == ':') {
				return false;
			}
			// i.e. "\\path1\" or "\\?\UNC\"
			if (path[0] == '\\' && path[1] == '\\') {
				return false;
			}
			return true;
		}

		bool is_disk_relative(const char *path, size_t path_len)
		{
			if (path_len < 2) {
				return true;
			}
			//check format:
			if ((path[0] >= 'a' && path[0] <= 'z')
				|| (path[0] >= 'A' && path[0] <= 'Z'))
			{
				if (path[1] == ':') {
					// format i.e: C:\...
					return true;
				}
			}
			return false;
		}

		std::string remap_to_drive_letter(std::string full_path)
		{
			size_t full_path_size = full_path.length();
			if (full_path_size == 0) {
				return full_path;
			}

			DWORD drives_bitmask = GetLogicalDrives();
			//std::cout << "Drives: " << std::hex << drives_bitmask << std::endl;

			for (DWORD i = 0; i < 32; i += 1, drives_bitmask >>= 1) {
				if ((drives_bitmask & 1) == 1) {
					char letter[] = "?:";
					letter[0] = 'A' + (char)i;
					//std::cout << "Drive: " << letter << std::endl;
					char out_path[MAX_PATH] = { 0 };
					if (!QueryDosDeviceA(letter, out_path, MAX_PATH)) {
						return full_path;
					}
					//QueryDosDeviceA returns all possible mappings pointing to this drive letter, divided by a delimiter: ";"
					//sometimes one device letter is mapped to several paths
					// i.e. "\Device\VBoxMiniRdr\;E:\vboxsrv\vm_shared"
					const char delim[] = ";";
					char *next_token = nullptr;

					char * pch = strtok_s(out_path, delim, &next_token);
					while (pch != nullptr) {
						// check if the current path starts from any of the mapped paths
						std::size_t found = full_path.find(pch);
						if (found != std::string::npos && found == 0) {
							size_t dir_len = strlen(pch);
							//if so, cut out the mappining path/device path and replace it with a drive letter
							std::string str2 = full_path.substr(dir_len, full_path_size);
							if (str2[0] != '/' && str2[0] != '\\') {
								str2 = "\\" + str2;
							}
							return letter + str2;
						}
						pch = strtok_s(nullptr, delim, &next_token);
					}
				}
			}
			return full_path;
		}

		std::string relative_to_absolute_path(std::string path)
		{
			if (is_relative(path.c_str(), path.length())) {
				char current_dir[MAX_PATH] = { 0 };
				GetCurrentDirectoryA(MAX_PATH, current_dir);
				path = std::string(current_dir) + "\\" + path;
			}
			char out_path[MAX_PATH] = { 0 };
			PathCanonicalizeA(out_path, path.c_str());
			return std::string(out_path);
		}

		std::string replace_char(std::string &str, char ch1, char ch2) {
			for (size_t i = 0; i < str.length(); ++i) {
				if (str[i] == ch1)
					str[i] = ch2;
			}
			return str;
		}
	};
};

bool pesieve::util::convert_to_wow64_path(char *szModName)
{
	init_syspaths();
	if (!get_subpath_ptr(szModName, g_System32Path)) {
		return false;
	}
	size_t sysPathLen = strlen(g_Syswow64Path);
	memcpy(szModName, g_Syswow64Path, sysPathLen);
	return true;
}

std::string pesieve::util::convert_to_win32_path(const std::string &path)
{
	std::string stripped_path = strip_prefix(path, LONG_PATH_PREFIX);
	if (stripped_path.length() < 3) {
		return "";
	}
	//check format:
	if (is_disk_relative(stripped_path.c_str(), stripped_path.length())) {
		return stripped_path;
	}
	stripped_path = strip_prefix(stripped_path, GLOBALROOT_NAME);
	const char *szModName = stripped_path.c_str();
	std::wstring unicode_name(szModName, szModName + strlen(szModName));
	HANDLE hFile = nt_create_file(unicode_name.c_str());
	if (hFile == nullptr) {
		return "";
	}
	std::string my_path = nt_retrieve_file_path(hFile);
	CloseHandle(hFile);
	return my_path;
}

std::string pesieve::util::device_path_to_win32_path(const std::string &full_path)
{
	std::string path = full_path;
	//sometimes mapping can be recursive, so resolve it till the root
	do {
		std::string remapped_path = remap_to_drive_letter(path);
		if (remapped_path == path) break;
		path = remapped_path;
	} while (true);
	return path;
}

bool is_device_path(std::string path)
{
	const std::string device_path = "\\Device\\";
	if (path.length() < device_path.length() || path[0] !='\\') {
		return false;
	}
	if (path.compare(0, device_path.length(), device_path) == 0){
		return true;
	}
	return false;
}

std::string pesieve::util::expand_path(std::string path)
{
	std::string basic_path = pesieve::util::device_path_to_win32_path(path);
	if (is_device_path(basic_path)) {
		// Could not normalize it: it is still a device path. Return as is.
		return path;
	}
	// normalize path sepators: use '/' not '\'
	replace_char(basic_path, '/', '\\');

	std::string abs_path = relative_to_absolute_path(basic_path);
	
	char filename[MAX_PATH] = { 0 };
	if (GetLongPathNameA(abs_path.c_str(), filename, MAX_PATH) == 0) {
		size_t len = abs_path.length();
		if (len > MAX_PATH) len = MAX_PATH;
		//if could not retrieve, process what you have:
		memcpy(filename, abs_path.c_str(), len);
	}
	return strip_prefix(filename, LONG_PATH_PREFIX);
}

