#include "thread_scanner.h"
#include <peconv.h>

using namespace pesieve;

typedef struct _thread_ctx {
	bool is64b;
	ULONGLONG rip;
	ULONGLONG rsp;
	ULONGLONG ret_addr;
} thread_ctx;

bool fetch_thread_ctx(HANDLE hProcess, HANDLE hThread, thread_ctx& c)
{
	bool is_ok = false;
	BOOL is_wow64 = FALSE;
#ifdef _WIN64
	pesieve::util::is_process_wow64(hProcess, &is_wow64);

	if (is_wow64) {
		WOW64_CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		if (Wow64GetThreadContext(hThread, &ctx)) {
			is_ok = true;

			c.rip = ctx.Eip;
			c.rsp = ctx.Esp;
			c.is64b = false;
		}
	}
#endif
	if (!is_ok) {

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		if (GetThreadContext(hThread, &ctx)) {
			is_ok = true;
#ifdef _WIN64
			c.rip = ctx.Rip;
			c.rsp = ctx.Rsp;
			c.is64b = true;
#else
			c.rip = ctx.Eip;
			c.rsp = ctx.Esp;
			c.is64b = false;
#endif
		}
	}
	return is_ok;
}

bool pesieve::ThreadScanner::resolveAddr(ULONGLONG addr)
{
	bool is_resolved = false;
	ScannedModule* mod = modulesInfo.findModuleContaining(addr);
	std::cout << " > " << std::hex << addr;
	if (mod) {
		std::cout << " : " << mod->getModName();
		is_resolved = true;
	}
	if (exportsMap) {
		const peconv::ExportedFunc* exp = exportsMap->find_export_by_va(addr);
		if (exp) {
			std::cout << " : " << exp->toString();
			is_resolved = true;
		}
	}
	std::cout << std::endl;
	return is_resolved;
}

ThreadScanReport* pesieve::ThreadScanner::scanRemote()
{
	HANDLE hThread = OpenThread(
		THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE,
		FALSE,
		tid
	);
	if (!hThread) {
		std::cerr << "[-] Could not OpenThread. Error: " << GetLastError() << std::endl;
		return nullptr;
	}

	ThreadScanReport* my_report = new ThreadScanReport(tid);
	thread_ctx c = { 0 };
	bool is_ok = fetch_thread_ctx(processHandle, hThread, c);
	CloseHandle(hThread);

	if (!is_ok) {
		my_report->status = SCAN_ERROR;
		return my_report;
	}

	if (c.is64b) {
		ULONGLONG my_ret = 0;
		if (peconv::read_remote_memory(processHandle, (LPVOID)c.rsp, (BYTE*)&my_ret, sizeof(my_ret), sizeof(my_ret)) == sizeof(my_ret)) {
			c.ret_addr = my_ret;
		}
	}
	else {
		DWORD my_ret = 0;
		if (peconv::read_remote_memory(processHandle, (LPVOID)c.rsp, (BYTE*)&my_ret, sizeof(my_ret), sizeof(my_ret)) == sizeof(my_ret)) {
			c.ret_addr = my_ret;
		}
	}
	std::cout << std::hex << "Tid: " << tid << " b:" << c.is64b << " Rip: " << c.rip << " Rsp: " << c.rsp;
	if (c.ret_addr != 0) {
		std::cout << std::hex << " Ret: " << c.ret_addr;
	}
	std::cout << "\n";
	resolveAddr(c.rip);
	if (c.ret_addr != 0) {
		resolveAddr(c.ret_addr);
	}
	return my_report;
}
