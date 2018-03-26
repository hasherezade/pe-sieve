#include "path_converter.h"

#include <Windows.h>

#include "ntddk.h"
#pragma comment(lib, "Ntdll.lib")

#include <iostream>
#include <string>
#include <locale>
#include <codecvt>

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
	wchar_t my_buffer[MAX_PATH] = { 0 };
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

	char buf[MAX_PATH];
	GetWindowsDirectory(buf, MAX_PATH);
	buf[2] = '\0'; // cut after the drive letter
	my_string = std::string(buf) + my_string;

	return my_string;
}

std::string convert_to_win32_path(std::string path)
{
	const char *szModName = path.c_str();
	std::wstring unicode_name(szModName, szModName + strlen(szModName));
	HANDLE hFile = nt_create_file(unicode_name.c_str());
	if (hFile == nullptr) {
		return "";
	}
	std::string my_path = nt_retrieve_file_path(hFile);
	CloseHandle(hFile);
	return my_path;
}

char get_drive_letter(std::string device_path)
{
	DWORD drives_bitmask = GetLogicalDrives();
	//std::cout << "Drives: " << std::hex << drives_bitmask << std::endl;

	for (DWORD i = 0; i < 32; i += 1, drives_bitmask >>= 1) {
		if ((drives_bitmask & 1) == 1) {
			char letter[] = "?:";
			letter[0] = 'A' + (char) i;
			//std::cout << "Drive: " << letter << std::endl;

			char out_path[MAX_PATH] = { 0 };
			if (!QueryDosDeviceA(letter, out_path, MAX_PATH)) {
				return 0;
			}
			//std::cout << "Path: " << out_path << std::endl;
			if (strstr(out_path, device_path.c_str())) {
				return letter[0];
			}
		}
	}
	return 0;;
}

std::string device_path_to_win32_path(std::string full_path)
{
	char token = '\\';
	const size_t full_path_len = full_path.length();
	const char *str = full_path.c_str();
	size_t split_point = 0;

	for (size_t i = 0, found = 0; i < full_path_len; i++) {
		if (full_path[i] == token) {
			found++;
			if (found == 3) { // found the split point
				split_point = i;
				break;
			}
			
		}
	}
	if (split_point == 0) {
		return "";
	}
	std::string dev_name = std::string(str, str + split_point);
	std::string dir_name = std::string(str + split_point, str + full_path_len);
	char dev_letter = get_drive_letter(dev_name);
	if (!dev_letter) return "";

	char letter[] = "?:";
	letter[0] = dev_letter;
	return letter + dir_name;
}

