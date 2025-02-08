#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <map>

namespace pesieve {
	namespace util {
		size_t extract_syscall_table(OUT std::map<DWORD, std::string>& syscallToName);
	}; //namespace util

	struct SyscallTable {

		static bool isSyscallDll(const std::string& libName)
		{
			if (libName == "ntdll.dll" || libName == "win32u.dll") {
				return true;
			}
			if (libName == "ntdll" || libName == "win32u") {
				return true;
			}
			return false;
		}

		static bool isSyscallFunc(const std::string& funcName, bool NtOnly = false)
		{
			if (funcName.empty() || funcName.length() < 3) {
				return false;
			}
			bool hasPrefix = false;
			if (!NtOnly) {
				if (funcName[0] == 'Z' && funcName[1] == 'w') {
					hasPrefix = true;
				}
			}
			if (funcName[0] == 'N' && funcName[1] == 't') {
				hasPrefix = true;
			}
			if (!hasPrefix) {
				return false;
			}
			if (funcName[2] >= 'A' && funcName[2] <= 'Z') {
				// the name of the function after the Nt prefix should start in uppercase,
				// syscalls are in functions like: NtUserSetWindowLongPtr, but not: NtdllDefWindowProc_A
				return true;
			}
			return false;
		}

		static bool isSameSyscallFunc(const std::string &func1, const std::string &func2)
		{
			if (func1 == func2) return true;

			std::string prefix1 = func1.substr(0, 2);
			std::string prefix2 = func2.substr(0, 2);

			if ((prefix1 == "Zw" || prefix1 == "Nt") && (prefix2 == "Zw" || prefix2 == "Nt")) {
				std::string body1 = func1.substr(2);
				std::string body2 = func2.substr(2);
				if (body1 == body2) {
					return true;
				}
				if (body1.length() == body2.length()) {
					return false;
				}
				// the difference may be in the suffix
				std::string* smaller_ptr = body1.length() < body2.length() ? &body1 : &body2;
				size_t smaller_size = smaller_ptr->length();
				if (body1.substr(0, smaller_size) == body2.substr(0, smaller_size)) {
					std::string* bigger_ptr = body1.length() > body2.length() ? &body1 : &body2;
					std::string suffix = bigger_ptr->substr(smaller_size);
					if (suffix == "32") {
						return true;
					}
				}
			}
			return false;
		}

		SyscallTable()
		{
			util::extract_syscall_table(this->syscallToName);
#ifdef _DEBUG
			std::cout << "Extracted syscalls: " << syscallToName.size() << "\n";
#endif
		}

		bool isReady()
		{
			return syscallToName.size() ? true : false;
		}

		std::string getSyscallName(DWORD id)
		{
			auto itr = syscallToName.find(id);
			if (itr != syscallToName.end()) {
				return itr->second;
			}
			return "";
		}

		std::map<DWORD, std::string> syscallToName;
	}; //struct SyscallTable

}; // namespace pesieve 
