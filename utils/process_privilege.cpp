#include "process_privilege.h"
#include "process_util.h"

#include <iostream>

namespace pesieve {
	namespace util {

		inline HMODULE get_or_load_module(const char* name)
		{
			HMODULE hndl = GetModuleHandleA(name);
			if (!hndl) {
				hndl = LoadLibraryA(name);
			}
			return hndl;
		}

		/*
		based on: https://support.microsoft.com/en-us/help/131065/how-to-obtain-a-handle-to-any-process-with-sedebugprivilege
		*/
		BOOL set_privilege(
			HANDLE hToken,          // token handle
			LPCTSTR Privilege,      // Privilege to enable/disable
			BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
		)
		{
			TOKEN_PRIVILEGES tp;
			LUID luid;
			TOKEN_PRIVILEGES tpPrevious;
			DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

			if (!LookupPrivilegeValueA(nullptr, Privilege, &luid)) {
				return FALSE;
			}
			// get current privilege
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = 0;

			AdjustTokenPrivileges(
				hToken,
				FALSE,
				&tp,
				sizeof(TOKEN_PRIVILEGES),
				&tpPrevious,
				&cbPrevious
			);

			if (GetLastError() != ERROR_SUCCESS) {
				return FALSE;
			}
			// set privilege based on previous setting
			tpPrevious.PrivilegeCount = 1;
			tpPrevious.Privileges[0].Luid = luid;

			if (bEnablePrivilege) {
				tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
			}
			else {
				tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes);
			}

			AdjustTokenPrivileges(
				hToken,
				FALSE,
				&tpPrevious,
				cbPrevious,
				NULL,
				NULL
			);

			if (GetLastError() != ERROR_SUCCESS) {
				return FALSE;
			}
			return TRUE;
		}

		BOOL _get_process_DEP_policy(HANDLE processHandle, DWORD &flags, BOOL &is_permanent)
		{
			//load the function GetProcessDEPPolicy dynamically, to provide backward compatibility with systems that don't have it
			HMODULE kernelLib = get_or_load_module("kernel32.dll");
			if (!kernelLib) return FALSE;

			FARPROC procPtr = GetProcAddress(kernelLib, "GetProcessDEPPolicy");
			if (!procPtr) return FALSE;

			BOOL(WINAPI *_GetProcessDEPPolicy)(HANDLE, LPDWORD, PBOOL) = (BOOL(WINAPI *)(HANDLE, LPDWORD, PBOOL))procPtr;
			return _GetProcessDEPPolicy(processHandle, &flags, &is_permanent);
		}

		DEP_SYSTEM_POLICY_TYPE _get_system_DEP_policy()
		{
			//load the function GetSystemDEPPolicy dynamically, to provide backward compatibility with systems that don't have it
			HMODULE kernelLib = get_or_load_module("kernel32.dll");
			if (!kernelLib) return DEPPolicyAlwaysOff;

			FARPROC procPtr = GetProcAddress(kernelLib, "GetSystemDEPPolicy");
			if (!procPtr) return DEPPolicyAlwaysOff; //in old systems where this function does not exist, DEP is Off

			DEP_SYSTEM_POLICY_TYPE(WINAPI *_GetSystemDEPPolicy)(VOID) = (DEP_SYSTEM_POLICY_TYPE(WINAPI *)(VOID))procPtr;
			return _GetSystemDEPPolicy();
		}

	};
};

bool pesieve::util::set_debug_privilege()
{
	HANDLE hToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) return false;
			if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)){
				std::cerr << "Error: cannot open the token" << std::endl;
				return false;
			}
		}
	}
	bool is_ok = false;
	// enable SeDebugPrivilege
	if (set_privilege(hToken, SE_DEBUG_NAME, TRUE)) {
		is_ok = true;
	}
	// close token handle
	CloseHandle(hToken);
	return is_ok;
}

pesieve::util::process_integrity_t translate_integrity_level(TOKEN_MANDATORY_LABEL *pTIL)
{
	DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
		(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

	if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
	{
		// Low Integrity
		return pesieve::util::INTEGRITY_LOW;
	}
	if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
		dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
	{
		// Medium Integrity
		return pesieve::util::INTEGRITY_MEDIUM;
	}
	if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
		dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
	{
		// High Integrity
		return pesieve::util::INTEGRITY_HIGH;
	}
	if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
	{
		// System Integrity
		return pesieve::util::INTEGRITY_SYSTEM;
	}
	return pesieve::util::INTEGRITY_UNKNOWN;
}

pesieve::util::process_integrity_t pesieve::util::get_integrity_level(HANDLE hProcess)
{
	if (!hProcess) {
		return INTEGRITY_UNKNOWN;
	}

	HANDLE hToken = NULL;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		//std::cerr << "[-][Cannot Open the ProcessToken" << std::endl;
		return INTEGRITY_UNKNOWN;
	}
	DWORD dwLength = sizeof(TOKEN_GROUPS);
	TOKEN_MANDATORY_LABEL *ptg = (TOKEN_MANDATORY_LABEL*) calloc(1, dwLength);

	if (!GetTokenInformation(
		hToken,         // handle to the access token
		TokenIntegrityLevel,    // get information about the token's groups 
		(LPVOID)ptg,   // pointer to TOKEN_MANDATORY_LABEL buffer
		0,              // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		free(ptg); ptg = nullptr;
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			CloseHandle(hToken);
			return INTEGRITY_UNKNOWN;
		}
		ptg = (TOKEN_MANDATORY_LABEL*)calloc(1, dwLength);
		if (!ptg) {
			//failed allocating
			CloseHandle(hToken);
			return INTEGRITY_UNKNOWN;
		}
	}
	process_integrity_t level = INTEGRITY_UNKNOWN;
	if (GetTokenInformation(
		hToken,         // handle to the access token
		TokenIntegrityLevel,    // get information about the token's groups 
		(LPVOID)ptg,   // pointer to TOKEN_MANDATORY_LABEL buffer
		dwLength,       // size of buffer
		&dwLength       // receives required buffer size
	))
	{
		level = translate_integrity_level(ptg);
	}
	//cleanup:
	free(ptg); ptg = nullptr;
	CloseHandle(hToken);
	return level;
}

bool pesieve::util::is_DEP_enabled(HANDLE processHandle)
{
	DEP_SYSTEM_POLICY_TYPE global_dep = _get_system_DEP_policy();
	if (global_dep == DEPPolicyAlwaysOff) {
		return false;
	}
	if (global_dep == DEPPolicyAlwaysOn) {
		return true;
	}
	// 
	DWORD flags = 0;
	BOOL is_permanent = FALSE;
	BOOL is_ok = _get_process_DEP_policy(processHandle, flags, is_permanent);
	if (!is_ok) {
#ifdef _WIN64
		BOOL isRemoteWow64 = FALSE;
		is_process_wow64(processHandle, &isRemoteWow64);
		if (!isRemoteWow64) {
			return true; // it is a 64 bit process, DEP is enabled
		}
#endif
#ifdef _DEBUG
		std::cerr << "Could not fetch the DEP status\n";
#endif
		return false;
	}
	const bool is_DEP = (flags & PROCESS_DEP_ENABLE) || (flags & PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION);
	return is_DEP;
}
