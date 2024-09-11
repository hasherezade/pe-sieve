#include "syscall_extractor.h"

#include <windows.h>
#include <peconv.h> // include libPeConv header
#include <iostream>
#include "process_util.h"

namespace pesieve {
	namespace util {

		bool isSyscallFunc(const std::string& funcName)
		{
			std::string prefix("Nt");
			if (funcName.size() < (prefix.size() + 1)) {
				return false;
			}
			if (funcName.compare(0, prefix.size(), prefix) != 0) {
				return false;
			}
			char afterPrefix = funcName.at(prefix.size());
			if (afterPrefix >= 'A' && afterPrefix <= 'Z') {
				// the name of the function after the Nt prefix will start in uppercase,
				// syscalls are in functions like: NtUserSetWindowLongPtr, but not: NtdllDefWindowProc_A
				return true;
			}
			return false;
		}

		size_t extract_syscalls(BYTE* pe_buf, size_t pe_size, std::map<DWORD, std::string>& syscallToName, size_t startID = 0)
		{
			std::vector<std::string> names_list;
			if (!peconv::get_exported_names(pe_buf, names_list)) {
				return 0;
			}

			std::map<DWORD, std::string> sys_functions;
			for (auto itr = names_list.begin(); itr != names_list.end(); ++itr) {
				std::string funcName = *itr;
				if (isSyscallFunc(funcName)) {
					ULONG_PTR va = (ULONG_PTR)peconv::get_exported_func(pe_buf, funcName.c_str());
					if (!va) continue;

					DWORD rva = DWORD(va - (ULONG_PTR)pe_buf);
					sys_functions[rva] = funcName;
				}
			}
			size_t id = startID;
			for (auto itr = sys_functions.begin(); itr != sys_functions.end(); ++itr) {
				std::string funcName = itr->second;
				syscallToName[id++] = funcName;
			}
			return id;
		}

		size_t extract_from_dll(IN const std::string& path, size_t startSyscallID, OUT std::map<DWORD, std::string>& syscallToName)
		{
			size_t bufsize = 0;
			BYTE* buffer = peconv::load_pe_module(path.c_str(), bufsize, false, false);

			if (!buffer) {
#ifdef _DEBUG
				std::cerr << "Failed to load the PE: " << path << "\n";
#endif
				return 0;
			}

			size_t extracted_count = extract_syscalls(buffer, bufsize, syscallToName, startSyscallID);
			peconv::free_pe_buffer(buffer);

			if (!extracted_count) {
#ifdef _DEBUG
				std::cerr << "No syscalls extracted from: " << path << "\n";
#endif
			}
			return extracted_count;
		}

	}; //namespace util

}; //namespace pesieve

size_t pesieve::util::extract_syscall_table(OUT std::map<DWORD, std::string>& syscallToName)
{
	PVOID old_val = NULL;
	pesieve::util::wow64_disable_fs_redirection(&old_val);

	std::stringstream outs;
	size_t extracted_count = 0;

	char ntdll_path[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\ntdll.dll", ntdll_path, MAX_PATH);
	extracted_count += extract_from_dll(ntdll_path, 0, syscallToName);

	char win32u_path[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA("%SystemRoot%\\system32\\win32u.dll", win32u_path, MAX_PATH);
	extracted_count += extract_from_dll(win32u_path, 0x1000, syscallToName);

	pesieve::util::wow64_revert_fs_redirection(&old_val);

	if (!extracted_count) {
#ifdef _DEBUG
		std::cerr << "Failed to extract syscalls.\n";
#endif
		return 0;
	}
	return syscallToName.size();
}
