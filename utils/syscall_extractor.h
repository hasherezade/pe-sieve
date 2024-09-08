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

		SyscallTable()
		{
			util::extract_syscall_table(this->syscallToName);
			std::cout << "Extracted syscalls: " << syscallToName.size() << "\n";
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
