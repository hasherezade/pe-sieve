#include "process_privilege.h"

#include <iostream>

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
	DWORD cbPrevious=sizeof(TOKEN_PRIVILEGES);

	if (!LookupPrivilegeValue(nullptr, Privilege, &luid)) {
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

	if(bEnablePrivilege) {
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

bool set_debug_privilege(DWORD process_id)
{
	HANDLE hToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)) {
		if (GetLastError() == ERROR_NO_TOKEN) {
			if (!ImpersonateSelf(SecurityImpersonation)) return false;
			if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)){
				std::cerr << "Error: cannor open the token" << std::endl;
				return false;
			}
		}
	}
	bool is_ok = false;
	// enable SeDebugPrivilege
	if (set_privilege(hToken, SE_DEBUG_NAME, TRUE)) {
		is_ok = true;
	} else {
		std::cerr << "Could not set debug privilege" << std::endl;
	}
	// close token handle
	CloseHandle(hToken);
	return is_ok;
}

process_integrity_t translate_integrity_level(TOKEN_MANDATORY_LABEL *pTIL)
{
	DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
		(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

	if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
	{
		// Low Integrity
		return INTEGRITY_LOW;
	}
	if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
		dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
	{
		// Medium Integrity
		return INTEGRITY_MEDIUM;
	}
	if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
		dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID)
	{
		// High Integrity
		return INTEGRITY_HIGH;
	}
	if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
	{
		// System Integrity
		return INTEGRITY_SYSTEM;
	}
	return INTEGRITY_UNKNOWN;
}

process_integrity_t get_integrity_level(HANDLE hProcess)
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
