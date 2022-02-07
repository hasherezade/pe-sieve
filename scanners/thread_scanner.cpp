#include "thread_scanner.h"
#include <peconv.h>
#include "../utils/process_util.h"
#include "../utils/ntddk.h"

#include <DbgHelp.h>
#pragma comment(lib, "dbghelp")

using namespace pesieve;

bool pesieve::ThreadScanner::isAddrInShellcode(ULONGLONG addr)
{
	ScannedModule* mod = modulesInfo.findModuleContaining(addr);
	if (!mod) return true;

	//the module is named
	if (mod->getModName().length() > 0) {
		return false;
	}
	return true;
}

size_t pesieve::ThreadScanner::enumStackFrames(HANDLE hProcess, HANDLE hThread, thread_ctx& c, IN LPVOID ctx)
{
	size_t fetched = 0;
	bool in_shc = false;
#ifdef _WIN64
	if (c.is64b) {
		STACKFRAME64 frame = { 0 };

		frame.AddrPC.Offset = c.rip;
		frame.AddrPC.Mode = AddrModeFlat;
		frame.AddrStack.Offset = c.rsp;
		frame.AddrStack.Mode = AddrModeFlat;
		frame.AddrFrame.Offset = c.rbp;
		frame.AddrFrame.Mode = AddrModeFlat;

		while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &frame, ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
			std::cout << "Next Frame start:" << std::hex << frame.AddrPC.Offset << "\n";
			const ULONGLONG next_addr = frame.AddrPC.Offset;
			c.call_stack.push_back(next_addr);
			c.ret_addr = next_addr;
			bool is_res = isAddrInShellcode(next_addr);
			if (is_res) {
				if (in_shc) break;
				in_shc = is_res;
				std::cout << "<-SHC\n";
			}
			fetched++;
		}
	}
#endif
	if (!c.is64b) {
		STACKFRAME frame = { 0 };

		frame.AddrPC.Offset = c.rip;
		frame.AddrPC.Mode = AddrModeFlat;
		frame.AddrStack.Offset = c.rsp;
		frame.AddrStack.Mode = AddrModeFlat;
		frame.AddrFrame.Offset = c.rbp;
		frame.AddrFrame.Mode = AddrModeFlat;

		while (StackWalk(IMAGE_FILE_MACHINE_I386, hProcess, hThread, &frame, ctx, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL)) {
			std::cout << "Next Frame start:" << std::hex << frame.AddrPC.Offset << "\n";
			const ULONGLONG next_addr = frame.AddrPC.Offset;
			c.call_stack.push_back(next_addr);
			c.ret_addr = next_addr;
			bool is_res = isAddrInShellcode(next_addr);
			this->resolveAddr(next_addr);
			if (is_res) {
				if (in_shc) break;
				in_shc = is_res;
				std::cout << "<-SHC\n";
			}
			fetched++;
		}
	}
	return fetched;
}

bool pesieve::ThreadScanner::fetchThreadCtx(IN HANDLE hProcess, IN HANDLE hThread, OUT thread_ctx& c)
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
			c.rbp = ctx.Ebp;
			c.is64b = false;
			enumStackFrames(hProcess, hThread, c, &ctx);
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
			c.rbp = ctx.Rbp;
			c.is64b = true;


#else
			c.rip = ctx.Eip;
			c.rsp = ctx.Esp;
			c.is64b = false;
#endif
			enumStackFrames(hProcess, hThread, c, &ctx);
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
	if (exportsMap && is_resolved) {
		bool search_name = false;
		if (mod->getModName() == "ntdll.dll" || mod->getModName() == "win32u.dll") {
			search_name = true;
		}
		for (size_t i = 0; i < 25; i++) {
			const peconv::ExportedFunc* exp = exportsMap->find_export_by_va(addr - i);
			if (exp) {
				std::cout << " : " << exp->toString();
				is_resolved = true;
				break;
			}
			if (!search_name) {
				break;
			}
		}
	}
	std::cout << std::endl;
	return is_resolved;
}

bool get_page_details(HANDLE processHandle, LPVOID start_va, MEMORY_BASIC_INFORMATION &page_info)
{
	size_t page_info_size = sizeof(MEMORY_BASIC_INFORMATION);
	const SIZE_T out = VirtualQueryEx(processHandle, (LPCVOID)start_va, &page_info, page_info_size);
	const bool is_read = (out == page_info_size) ? true : false;
	const DWORD error = is_read ? ERROR_SUCCESS : GetLastError();
	if (error != ERROR_SUCCESS) {//error == ERROR_INVALID_PARAMETER) {
		//nothing to read
		return false;
	}
	return true;
}

bool pesieve::ThreadScanner::reportSuspiciousAddr(ThreadScanReport* my_report, ULONGLONG susp_addr, thread_ctx  &c)
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	if (get_page_details(processHandle, (LPVOID)susp_addr, page_info)) {
		if (page_info.State & MEM_FREE) {
			return false;
		}
		ULONGLONG base = (ULONGLONG)page_info.BaseAddress;
		my_report->page_state = page_info.State;
		my_report->status = SCAN_SUSPICIOUS;
		my_report->module = (HMODULE)base;
		my_report->moduleSize = page_info.RegionSize;
		my_report->protection = page_info.AllocationProtect;

		my_report->thread_ip = susp_addr;
	}
	return true;
}


bool pesieve::ThreadScanner::InitSymbols(HANDLE hProc)
{
	if (SymInitialize(hProc, NULL, TRUE)) {
		return true;
	}
	return false;
}

bool pesieve::ThreadScanner::FreeSymbols(HANDLE hProc)
{
	if (SymCleanup(hProc)) {
		return true;
	}
	return false;
}

ThreadScanReport* pesieve::ThreadScanner::scanRemote()
{
	HANDLE hThread = OpenThread(
		THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE,
		FALSE,
		info.tid
	);
	if (!hThread) {
		std::cerr << "[-] Could not OpenThread. Error: " << GetLastError() << std::endl;
		return nullptr;
	}
	std::cout << std::dec << "---\nTid: " << info.tid << "\n";
	if (info.is_extended) {
		std::cout << " Start: " << std::hex << info.ext.start_addr << std::dec << " State: " << info.ext.state;
		if (info.ext.state == Waiting) {
			std::cout << " WaitReason: " << info.ext.wait_reason 
				<< " WaitTime: " << info.ext.wait_time;
		}
		std::cout << "\n";
		resolveAddr(info.ext.start_addr);
	}
	ThreadScanReport* my_report = new ThreadScanReport(info.tid);
	thread_ctx c = { 0 };
	bool is_ok = fetchThreadCtx(processHandle, hThread, c);

	DWORD exit_code = 0;
	GetExitCodeThread(hThread, &exit_code);

	CloseHandle(hThread);

	if (!is_ok) {
		my_report->status = SCAN_ERROR;
		return my_report;
	}

	std::cout << " b:" << c.is64b << std::hex << " Rip: " << c.rip << " Rsp: " << c.rsp; 
	if (exit_code != STILL_ACTIVE) 
		std::cout << " ExitCode: " << exit_code;

	if (c.ret_addr != 0) {
		std::cout << std::hex << " Ret: " << c.ret_addr;
	}
	std::cout << "\n";
	bool is_res = resolveAddr(c.rip);
	if (!is_res) {
		if (reportSuspiciousAddr(my_report, c.rip, c)) {
			return my_report;
		}
	}
	if (c.ret_addr != 0) {
		is_res = resolveAddr(c.ret_addr);
		if (!is_res) {
			if (reportSuspiciousAddr(my_report, c.ret_addr, c)) {
				return my_report;
			}
		}
	}
	return my_report;
}
