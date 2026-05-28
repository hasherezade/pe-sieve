#pragma once

#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

#include <iostream>
#include <mutex>
#include <unordered_map>
#include <string>

class DbgHelpWrapper
{
public:

	static bool InitializeProcess(HANDLE hProcess, const std::string& symbolPath, DWORD symOptions)
	{
		std::lock_guard<std::mutex> guard(m_Mutex);

		SessionInfo& session = sessions[hProcess];

		if (session.refCount > 0) {
			++session.refCount;
			return true;
		}

		SymSetOptions(symOptions);

		if (!SymInitialize(hProcess, symbolPath.empty() ? nullptr : symbolPath.c_str(), FALSE)) {
			session.lastError = GetLastError();
			return false;
		}

		if (!symbolPath.empty()) {
			SymSetSearchPath(hProcess, symbolPath.c_str());
		}

		session.initialized = true;
		session.refCount = 1;
		session.lastError = ERROR_SUCCESS;
		return true;
	}

	static bool CleanupProcess(HANDLE hProcess)
	{
		std::lock_guard<std::mutex> guard(m_Mutex);

		std::unordered_map<HANDLE, SessionInfo>::iterator it = sessions.find(hProcess);

		if (it == sessions.end()) {
			return true;
		}

		SessionInfo& session = it->second;

		if (session.refCount > 1) {
			--session.refCount;
			return true;
		}

		if (session.initialized) {
			if (!SymCleanup(hProcess)) {
				session.lastError = GetLastError();
				return false;
			}
		}
		sessions.erase(it);
		return true;
	}

	static bool RefreshModuleList(HANDLE hProcess)
	{
		std::lock_guard<std::mutex> guard(m_Mutex);

		if (!SymRefreshModuleList(hProcess)) {
			return false;
		}
		return true;
	}

	static bool FromAddress(HANDLE hProcess, DWORD64 address, PSYMBOL_INFO symbol, DWORD64* displacement)
	{
		std::lock_guard<std::mutex> guard(m_Mutex);
		if (!SymFromAddr(hProcess, address, displacement, symbol)) {
			return false;
		}
		return true;
	}

	static bool GetModuleInfo(HANDLE hProcess, DWORD64 address, IMAGEHLP_MODULE64* moduleInfo)
	{
		std::lock_guard<std::mutex> guard(m_Mutex);

		moduleInfo->SizeOfStruct = sizeof(IMAGEHLP_MODULE64);
		if (!SymGetModuleInfo64(hProcess, address, moduleInfo)) {
			return false;
		}
		return true;
	}

	static DWORD GetLastErrorForProcess(HANDLE hProcess)
	{
		std::lock_guard<std::mutex> guard(m_Mutex);

		auto it = sessions.find(hProcess);
		if (it == sessions.end()) {
			return ERROR_INVALID_HANDLE;
		}
		return it->second.lastError;
	}

private:

	struct SessionInfo
	{
		bool initialized;
		size_t refCount;
		DWORD lastError;

		SessionInfo()
			: initialized(false),
			refCount(0),
			lastError(ERROR_SUCCESS)
		{
		}
	};

	static std::mutex m_Mutex;
	static std::unordered_map< HANDLE, SessionInfo> sessions;
};
