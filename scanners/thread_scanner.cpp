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

size_t pesieve::ThreadScanner::enumStackFrames(IN HANDLE hProcess, IN HANDLE hThread, IN LPVOID ctx, IN OUT thread_ctx& c)
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
			//std::cout << "Next Frame start:" << std::hex << frame.AddrPC.Offset << "\n";
			const ULONGLONG next_addr = frame.AddrPC.Offset;
			c.ret_addr = next_addr;
			in_shc = isAddrInShellcode(next_addr);
#ifdef _DEBUG
			this->resolveAddr(next_addr);
#endif
			if (in_shc) break;
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
			//std::cout << "Next Frame start:" << std::hex << frame.AddrPC.Offset << "\n";
			const ULONGLONG next_addr = frame.AddrPC.Offset;
			c.ret_addr = next_addr;
			in_shc = isAddrInShellcode(next_addr);
#ifdef _DEBUG
			this->resolveAddr(next_addr);
#endif
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
			enumStackFrames(hProcess, hThread, &ctx, c);
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
			enumStackFrames(hProcess, hThread, &ctx, c);
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
	if (error != ERROR_SUCCESS) {
		//nothing to read
		return false;
	}
	return true;
}

bool pesieve::ThreadScanner::reportSuspiciousAddr(ThreadScanReport* my_report, ULONGLONG susp_addr, thread_ctx  &c)
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	if (!get_page_details(processHandle, (LPVOID)susp_addr, page_info)) {
		return false;
	}
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

// if extended info given, allow to filter out from the scan basing on the thread state and conditions
bool should_scan(const util::thread_info& info)
{
	if (!info.is_extended) {
		return true;
	}
	const KTHREAD_STATE state = (KTHREAD_STATE)info.ext.state;
	if (state == Running || state == Ready) {
		return true;
	}
	if (state == Terminated) {
		return false;
	}
	if (state == Waiting) {
		if (info.ext.wait_reason == DelayExecution
			|| info.ext.wait_reason == Suspended
			|| info.ext.wait_reason == Executive)
		{
			return true;
		}
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
#ifdef _DEBUG
		std::cerr << "[-] Could not OpenThread. Error: " << GetLastError() << std::endl;
#endif
		return nullptr;
	}
#ifdef _DEBUG
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
#endif
	ThreadScanReport* my_report = new ThreadScanReport(info.tid);
#ifndef _DEBUG
	// if NOT compiled in a debug mode, make this check BEFORE scan
	if (!should_scan(info)) {
		CloseHandle(hThread); // close the opened thread
		my_report->status = SCAN_NOT_SUSPICIOUS;
		return my_report;
	}
#endif
	thread_ctx c = { 0 };
	const bool is_ok = fetchThreadCtx(processHandle, hThread, c);

	DWORD exit_code = 0;
	GetExitCodeThread(hThread, &exit_code);
	CloseHandle(hThread);

	if (!is_ok) {
		// could not fetch the thread context and information
		my_report->status = SCAN_ERROR;
		return my_report;
	}
#ifdef _DEBUG
	std::cout << " b:" << c.is64b << std::hex << " Rip: " << c.rip << " Rsp: " << c.rsp; 
	if (exit_code != STILL_ACTIVE) 
		std::cout << " ExitCode: " << exit_code;

	if (c.ret_addr != 0) {
		std::cout << std::hex << " Ret: " << c.ret_addr;
	}
	std::cout << "\n";
#endif

	if (exit_code != STILL_ACTIVE) {
		my_report->status = SCAN_NOT_SUSPICIOUS;
		return my_report;
	}
#ifdef _DEBUG
	// if compiled in a debug mode, make this check AFTER scan
	// (so that we can see first what was skipped)
	if (!should_scan(info)) {
		my_report->status = SCAN_NOT_SUSPICIOUS;
		return my_report;
	}
#endif
	bool is_shc = isAddrInShellcode(c.rip);
	if (is_shc) {
		if (reportSuspiciousAddr(my_report, c.rip, c)) {
			return my_report;
		}
	}
	if (c.ret_addr != 0) {
		is_shc = isAddrInShellcode(c.ret_addr);
		if (is_shc) {
			if (reportSuspiciousAddr(my_report, c.ret_addr, c)) {
				return my_report;
			}
		}
	}
	return my_report;
}
