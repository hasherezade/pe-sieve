#include "thread_scanner.h"
#include <peconv.h>
#include "mempage_data.h"
#include "../utils/process_util.h"
#include "../utils/ntddk.h"
#include "../stats/stats.h"
#include "../utils/process_symbols.h"
#include "../utils/syscall_extractor.h"

extern pesieve::SyscallTable g_SyscallTable;

#define ENTROPY_TRESHOLD 3.0
//#define NO_ENTROPY_CHECK

#ifdef _DEBUG
#define _SHOW_THREAD_INFO
#endif

using namespace pesieve;

typedef struct _t_stack_enum_params {
	bool is_ok;
	HANDLE hProcess;
	HANDLE hThread;
	LPVOID ctx;
	const pesieve::ctx_details* cDetails;
	std::vector<ULONGLONG> callStack;

	_t_stack_enum_params(IN HANDLE _hProcess = NULL, IN HANDLE _hThread = NULL, IN LPVOID _ctx = NULL, IN const pesieve::ctx_details* _cDetails = NULL)
		: is_ok(false),
		hProcess(_hProcess), hThread(_hThread), ctx(_ctx), cDetails(_cDetails)
	{
	}

} t_stack_enum_params;

//---

namespace pesieve {

	bool is_thread_running(HANDLE hThread)
	{
		DWORD exit_code = 0;
		if (GetExitCodeThread(hThread, &exit_code)) {
			if (exit_code != STILL_ACTIVE) {
#ifdef _DEBUG
				std::cout << " Thread ExitCode: " << std::dec << exit_code << "\n";
#endif
				return false;
			}
		}
		return true;
	}

};

bool get_page_details(HANDLE processHandle, LPVOID start_va, MEMORY_BASIC_INFORMATION& page_info)
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

DWORD WINAPI enum_stack_thread(LPVOID lpParam)
{
	t_stack_enum_params* args = static_cast<t_stack_enum_params*>(lpParam);
	if (!args || !args->cDetails || !args->ctx) {
		return STATUS_INVALID_PARAMETER;
	}
	size_t fetched = 0;
	const pesieve::ctx_details& cDetails = *(args->cDetails);
#ifdef _WIN64
	if (cDetails.is64b) {
		STACKFRAME64 frame = { 0 };

		frame.AddrPC.Offset = cDetails.rip;
		frame.AddrPC.Mode = AddrModeFlat;
		frame.AddrStack.Offset = cDetails.rsp;
		frame.AddrStack.Mode = AddrModeFlat;
		frame.AddrFrame.Offset = cDetails.rbp;
		frame.AddrFrame.Mode = AddrModeFlat;

		while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, args->hProcess, args->hThread, &frame, args->ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
			const ULONGLONG next_addr = frame.AddrPC.Offset;
			args->callStack.push_back(next_addr);
			fetched++;
		}
	}
#endif
	if (!cDetails.is64b) {
		STACKFRAME frame = { 0 };

		frame.AddrPC.Offset = cDetails.rip;
		frame.AddrPC.Mode = AddrModeFlat;
		frame.AddrStack.Offset = cDetails.rsp;
		frame.AddrStack.Mode = AddrModeFlat;
		frame.AddrFrame.Offset = cDetails.rbp;
		frame.AddrFrame.Mode = AddrModeFlat;

		while (StackWalk(IMAGE_FILE_MACHINE_I386, args->hProcess, args->hThread, &frame, args->ctx, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL)) {
			const ULONGLONG next_return = frame.AddrPC.Offset;
			args->callStack.push_back(next_return);
			fetched++;
		}
	}
	if (fetched) {
		args->is_ok = true;
		return STATUS_SUCCESS;
	}
	return STATUS_UNSUCCESSFUL;
}

bool has_empty_gui_info(DWORD tid)
{
	GUITHREADINFO gui = { 0 };
	gui.cbSize = sizeof(GUITHREADINFO);
	if (!GetGUIThreadInfo(tid, &gui)) {
		return false;
	}
	bool hasWindows = gui.hwndActive || gui.hwndCapture || gui.hwndCaret || gui.hwndMenuOwner || gui.hwndMoveSize;
	bool hasRcCaret = gui.rcCaret.left || gui.rcCaret.right || gui.rcCaret.bottom || gui.rcCaret.top;
	if (hasWindows || hasRcCaret) {
		return false;
	}
	return true;
}

//---

std::string ThreadScanReport::translate_wait_reason(DWORD thread_wait_reason)
{
	switch (thread_wait_reason) {
		case DelayExecution: return "DelayExecution";
		case Suspended: return "Suspended";
		case Executive: return "Executive";
		case UserRequest: return "UserRequest";
		case WrUserRequest: return "WrUserRequest";
		case WrEventPair: return "WrEventPair";
		case WrQueue: return "WrQueue";
	}
	std::stringstream ss;
	ss << "Other: " << std::dec << thread_wait_reason;
	return ss.str();
}

std::string ThreadScanReport::translate_thread_state(DWORD thread_state)
{
	switch (thread_state) {
		case Initialized: return "Initialized";
		case Ready: return "Ready";
		case Running: return "Running";
		case Standby: return "Standby";
		case Terminated: return "Terminated";
		case Waiting: return "Waiting";
		case Transition: return "Transition";
		case DeferredReady: return "DeferredReady";
		case GateWaitObsolete: return "GateWaitObsolete";
		case WaitingForProcessInSwap: return "WaitingForProcessInSwap";
	}
	std::stringstream ss;
	ss << "Other: " << std::dec << thread_state;
	return ss.str();
}

//---

bool pesieve::ThreadScanner::checkReturnAddrIntegrity(IN const std::vector<ULONGLONG>& callStack)
{
	if (this->info.last_syscall == INVALID_SYSCALL || !symbols || !callStack.size() || !info.is_extended || !g_SyscallTable.isReady()) {
		return true; // skip the check
	}
	const std::string syscallFuncName = g_SyscallTable.getSyscallName(this->info.last_syscall);

	const ULONGLONG lastCalled = *callStack.begin();
	std::string lastFuncCalled = symbols->funcNameFromAddr(lastCalled);
	std::string manualSymbol = exportsMap ? resolveLowLevelFuncName(lastCalled) : "";
	if (lastFuncCalled.empty()) {
		if (!exportsMap) {
			return true; // skip the check
		}
		lastFuncCalled = manualSymbol;
	}
	if (callStack.size() == 1) {
		if (this->info.ext.wait_reason == Suspended && lastFuncCalled == "RtlUserThreadStart" && this->info.last_syscall == 0) {
			return true; //normal for suspended threads
		}
		return false; // otherwise it is an anomaly
	}
	// Proceed to check if the last syscall matches the last function called...
	if (this->info.ext.wait_reason == Suspended) {
		return true; // there can be last func. vs last syscall mismatch in case of suspended threads
	}
#ifndef _WIN64
	static bool isWow64 = util::is_current_wow64();
	if (!isWow64 && lastFuncCalled == "KiFastSystemCallRet") {
		return true;
	}
#endif
	if (SyscallTable::isSameSyscallFunc(syscallFuncName, lastFuncCalled)) {
		return true;
	}
	if (syscallFuncName == "NtCallbackReturn") {
		const ScannedModule* mod = modulesInfo.findModuleContaining(lastCalled);
		if (mod && mod->getModName() == "win32u.dll") return true;
	}

	if (this->info.ext.wait_reason == WrUserRequest || this->info.ext.wait_reason == UserRequest) {
		if (syscallFuncName.rfind("NtUser", 0) == 0 && (lastFuncCalled.rfind("NtUser", 0) == 0)) {
			return true;
		}
		if (syscallFuncName.rfind("NtGdi", 0) == 0 && (lastFuncCalled.rfind("NtUser", 0) == 0)) {
			return true;
		}
	}
	if (this->info.ext.wait_reason == UserRequest) {
		if (syscallFuncName.rfind("NtWaitFor", 0) == 0 && (lastFuncCalled.rfind("NtWaitFor", 0) == 0)) {
			return true;
		}
		if (syscallFuncName == "NtWaitForSingleObject" && (lastFuncCalled.rfind("NtQuery", 0) == 0) || lastFuncCalled == "NtDelayExecution") {
			return true;
		}
		if (syscallFuncName.rfind("NtGdi", 0) == 0 && (lastFuncCalled.rfind("NtGdi", 0) == 0)) {
			return true;
		}
		if (syscallFuncName.rfind("NtGdiDdDDIWaitFor", 0) == 0 && (lastFuncCalled.rfind("NtWaitFor", 0) == 0)) {
			return true;
		}
		if (syscallFuncName.rfind("NtUser", 0) == 0 && (lastFuncCalled.rfind("NtGdi", 0) == 0)) {
			return true;
		}
	}
	if (this->info.ext.wait_reason == WrQueue) {
		if (syscallFuncName == "NtWaitForSingleObject" && lastFuncCalled == "NtWaitForWorkViaWorkerFactory") {
			return true;
		}
		if (syscallFuncName == "NtWaitForWorkViaWorkerFactory" && lastFuncCalled == "NtWaitForSingleObject") {
			return true;
		}
	}
	if (this->info.ext.wait_reason == DelayExecution) {
		if (syscallFuncName == "NtDelayExecution" && ((lastFuncCalled.rfind("NtUserMsgWaitFor", 0) == 0) || (lastFuncCalled.rfind("NtWaitFor", 0) == 0))) {
			return true;
		}
	}
	const ScannedModule* mod = modulesInfo.findModuleContaining(lastCalled);
	const std::string mod_name = mod ? mod->getModName() : "";
	std::cout << "[@]" << std::dec << info.tid << " : " << "LastSyscall: " << syscallFuncName << " VS LastCalledAddr: " << std::hex << lastCalled << " : " << lastFuncCalled << "(" << mod_name << "." << manualSymbol <<" )" << " DIFFERENT!" << " WaitReason: " << std::dec << this->info.ext.wait_reason << std::endl;
#ifdef _SHOW_THREAD_INFO
	printThreadInfo(info);
	std::cout << "STACK:\n";
	for (auto itr = callStack.rbegin(); itr != callStack.rend(); ++itr) {
		ULONGLONG next_return = *itr;
		symbols->dumpSymbolInfo(next_return);
		std::cout << "\t";
		printResolvedAddr(next_return);
	}
	std::cout << std::endl;
#endif //_SHOW_THREAD_INFO
	return false;
}

size_t pesieve::ThreadScanner::analyzeCallStack(IN const std::vector<ULONGLONG> &call_stack, IN OUT ctx_details& cDetails)
{
	size_t processedCntr = 0;

	cDetails.is_managed = false;
	cDetails.stackFramesCount = call_stack.size();
	cDetails.is_ret_in_frame = false;
#ifdef _SHOW_THREAD_INFO
	std::cout << "\n" << "Stack frame Size: " << std::dec << call_stack.size() << "\n===\n";
#endif //_SHOW_THREAD_INFO
	for (auto itr = call_stack.rbegin(); itr != call_stack.rend() ;++itr, ++processedCntr) {
		const ULONGLONG next_return = *itr;
		if (cDetails.ret_on_stack == next_return) {
			cDetails.is_ret_in_frame = true;
		}
#ifdef _SHOW_THREAD_INFO
		if (symbols) {
			symbols->dumpSymbolInfo(next_return);
		}
		std::cout << "\t";
		printResolvedAddr(next_return);
#endif //_SHOW_THREAD_INFO
		bool is_curr_shc = false;
		const ScannedModule* mod = modulesInfo.findModuleContaining(next_return);
		const std::string mod_name = mod ? mod->getModName() : "";
		if (mod_name.length() == 0) {
			if (!cDetails.is_managed) {
				is_curr_shc = true;
				cDetails.shcCandidates.insert(next_return);
#ifdef _SHOW_THREAD_INFO
				std::cout << "\t" << std::hex << next_return << " <=== SHELLCODE\n";
#endif //_SHOW_THREAD_INFO
			} else {
#ifdef _SHOW_THREAD_INFO
				std::cout << "\t" << std::hex << next_return << " <=== .NET JIT\n";
#endif //_SHOW_THREAD_INFO
			}
		}
		if (!is_curr_shc) {
			// store the last address, till the first called shellcode:
			cDetails.last_ret = next_return;
		}
		// check if the found shellcode is a .NET JIT:
		if (mod_name == "clr.dll" || mod_name == "coreclr.dll") {
			cDetails.is_managed = true;
#ifdef _SHOW_THREAD_INFO
			std::cout << "\t" << std::hex << next_return << " <--- .NET\n";
#endif //_SHOW_THREAD_INFO
		}
	}
#ifdef _SHOW_THREAD_INFO
	std::cout << "\n===\n";
#endif //_SHOW_THREAD_INFO
	return processedCntr;
}

size_t pesieve::ThreadScanner::fillCallStackInfo(IN HANDLE hProcess, IN HANDLE hThread, IN LPVOID ctx, IN OUT ctx_details& cDetails)
{
	// do it in a new thread to prevent stucking...
	t_stack_enum_params args(hProcess, hThread, ctx, &cDetails);

	const size_t max_wait = 1000;
	{
		HANDLE enumThread = CreateThread(
			NULL,                   // default security attributes
			0,                      // use default stack size  
			enum_stack_thread,       // thread function name
			&args,          // argument to thread function 
			0,                      // use default creation flags 
			0);   // returns the thread identifiee

		if (enumThread) {
			DWORD wait_result = WaitForSingleObject(enumThread, max_wait);
			if (wait_result == WAIT_TIMEOUT) {
				std::cerr << "[!] Cannot retrieve stack frame: timeout passed!\n";
				TerminateThread(enumThread, 0);
				CloseHandle(enumThread);
				return 0;
			}
			CloseHandle(enumThread);
		}
	}
	if (!args.is_ok) {
		return 0;
	}
#ifdef _SHOW_THREAD_INFO
	std::cout << "\n=== TID " << std::dec << GetThreadId(hThread) << " ===\n";
#endif //_SHOW_THREAD_INFO
	const size_t analyzedCount = analyzeCallStack(args.callStack, cDetails);
	if (!cDetails.is_managed) {
		cDetails.is_ret_as_syscall = checkReturnAddrIntegrity(args.callStack);
	}
	return analyzedCount;
}

template <typename PTR_T>
bool read_return_ptr(IN HANDLE hProcess, IN OUT ctx_details& cDetails) {
	PTR_T ret_addr = 0;
	cDetails.ret_on_stack = 0;
	if (peconv::read_remote_memory(hProcess, (LPVOID)cDetails.rsp, (BYTE*)&ret_addr, sizeof(ret_addr)) == sizeof(ret_addr)) {
		cDetails.ret_on_stack = (ULONGLONG)ret_addr;
		return true;
	}
	return false;
}

bool pesieve::ThreadScanner::fetchThreadCtxDetails(IN HANDLE hProcess, IN HANDLE hThread, OUT ctx_details& cDetails)
{
	bool is_ok = false;
	BOOL is_wow64 = FALSE;
	size_t retrieved = 0;
#ifdef _WIN64
	pesieve::util::is_process_wow64(hProcess, &is_wow64);

	if (is_wow64) {
		WOW64_CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		if (pesieve::util::wow64_get_thread_context(hThread, &ctx)) {
			is_ok = true;
			cDetails.init(false, ctx.Eip, ctx.Esp, ctx.Ebp);
			read_return_ptr<DWORD>(hProcess, cDetails);
			retrieved = fillCallStackInfo(hProcess, hThread, &ctx, cDetails);
		}
	}
#endif
	if (!is_ok) {

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		if (GetThreadContext(hThread, &ctx)) {
			is_ok = true;
#ifdef _WIN64
			cDetails.init(true, ctx.Rip, ctx.Rsp, ctx.Rbp);
			read_return_ptr<ULONGLONG>(hProcess, cDetails);
#else
			cDetails.init(false, ctx.Eip, ctx.Esp, ctx.Ebp);
			read_return_ptr<DWORD>(hProcess, cDetails);
#endif
			retrieved = fillCallStackInfo(hProcess, hThread, &ctx, cDetails);
		}
	}
	if (!retrieved) is_ok = false;
	return is_ok;
}

bool pesieve::ThreadScanner::isAddrInNamedModule(const ULONGLONG addr)
{
	ScannedModule* mod = modulesInfo.findModuleContaining(addr);
	if (!mod) return false;

	//the module is named
	if (mod->getModName().length() > 0) {
		return true;
	}
	return false;
}

std::string pesieve::ThreadScanner::resolveLowLevelFuncName(const ULONGLONG addr, size_t maxDisp)
{
	if (!exportsMap) {
		return "";
	}
	ScannedModule* mod = modulesInfo.findModuleContaining(addr);
	if (!mod) {
		return "";
	}
	if (mod->getModName() != "ntdll.dll" && mod->getModName() != "win32u.dll") {
		// not a DLL containing a syscall
		return "";
	}
	bool is_resolved = false;
	std::string func;
	for (size_t disp = 0; disp < maxDisp; disp++) {
		const peconv::ExportedFunc* exp = exportsMap->find_export_by_va(addr - disp);
		if (exp) {
			return exp->nameToString();
		}
	}
	return "";
}

bool pesieve::ThreadScanner::printResolvedAddr(const ULONGLONG addr)
{
	bool is_resolved = false;
	std::cout << std::hex << addr;
	ScannedModule* mod = modulesInfo.findModuleContaining(addr);
	if (mod) {
		std::cout << " : " << mod->getModName();
		is_resolved = true;
	}
	std::cout << " : " << resolveLowLevelFuncName(addr);
	std::cout << std::endl;
	return is_resolved;
}

void pesieve::ThreadScanner::printThreadInfo(const pesieve::util::thread_info& threadi)
{
	std::cout << std::dec << "TID: " << threadi.tid << "\n";
	std::cout << std::hex << "\tStart   : ";
	printResolvedAddr(threadi.start_addr);

	if (threadi.is_extended) {
		std::cout << std::hex << "\tSysStart: ";
		printResolvedAddr(threadi.ext.sys_start_addr);
		if (threadi.last_syscall != INVALID_SYSCALL) {
			std::cout << "\tLast Syscall: " << std::hex << threadi.last_syscall << " Func: " << g_SyscallTable.getSyscallName(threadi.last_syscall) << std::endl;
		}
		std::cout << "\tState: [" << ThreadScanReport::translate_thread_state(threadi.ext.state) << "]";
		if (threadi.ext.state == Waiting) {
			std::cout << " Reason: [" << ThreadScanReport::translate_wait_reason(threadi.ext.wait_reason) << "] Time: " << threadi.ext.wait_time;
		}
		std::cout << "\n";
	}
	std::cout << "\n";
}

bool ThreadScanReport::AreaInfo::fillStats(HANDLE processHandle, bool isReflection)
{
	ULONG_PTR end_va = (ULONG_PTR)base + regionSize;
	MemPageData mem(processHandle, isReflection, (ULONG_PTR)base, end_va);
	if (!mem.fillInfo() || !mem.load()) {
		return false;
	}
	AreaStatsCalculator calc(mem.loadedData);
	return calc.fill(stats, nullptr);
}

ThreadScanReport::AreaInfo* ThreadScanReport::AreaInfo::fillInfo(HANDLE processHandle, bool isReflection, ULONGLONG susp_addr)
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	if (!get_page_details(processHandle, (LPVOID)susp_addr, page_info)) {
		return nullptr;
	}
	if (page_info.State & MEM_FREE) {
		return nullptr;
	}

	ULONG_PTR base = (ULONG_PTR)page_info.BaseAddress;
	ThreadScanReport::AreaInfo* info = new ThreadScanReport::AreaInfo(base, page_info.RegionSize, page_info.AllocationProtect);
	info->fillStats(processHandle, isReflection);
	return info;
}

ThreadScanReport::AreaInfo* pesieve::ThreadScanReport::makeInfoForAddress(HANDLE processHandle, bool isReflection, ULONG_PTR address)
{
	ThreadScanReport::AreaInfo* info = getInfoForAddress(susp_addr);
	if (!info) {
		info = ThreadScanReport::AreaInfo::fillInfo(processHandle, isReflection, susp_addr);
		if (!info) {
			return nullptr;
		}
		suspiciousAreas[info->base] = info;
	}
	return info;
}

bool pesieve::ThreadScanner::reportSuspiciousAddr(ThreadScanReport* my_report, ULONGLONG susp_addr)
{
	ThreadScanReport::AreaInfo* info = my_report->makeInfoForAddress(this->processHandle, this->isReflection, susp_addr);
	if (!info) {
		return false;
	}
	my_report->susp_addr = susp_addr;
	my_report->protection = info->allocationProtect;

#ifndef NO_ENTROPY_CHECK
	if (info->stats.isFilled() && (info->stats.entropy >= ENTROPY_TRESHOLD)) {
		my_report->module = (HMODULE)info->base;
		my_report->moduleSize = info->regionSize;
		my_report->indicators.insert(THI_SUS_CALLSTACK_SHC);
		return true;
	}
	my_report->status = SCAN_NOT_SUSPICIOUS;
	return false;
#else
	return true;
#endif
}

// if extended info given, allow to filter out from the scan basing on the thread state and conditions
bool should_scan_context(const util::thread_info& info)
{
	if (!info.is_extended) {
		return true;
	}
	const KTHREAD_STATE state = (KTHREAD_STATE)info.ext.state;
	if (state == Ready) {
		return true;
	}
	if (state == Terminated) {
		return false;
	}
	if (state == Waiting && info.ext.wait_reason <= WrQueue) {
		return true;
	}
	return false;
}

bool pesieve::ThreadScanner::scanRemoteThreadCtx(HANDLE hThread, ThreadScanReport* my_report)
{
	const DWORD tid = info.tid;
	ctx_details cDetails;
	const bool is_ok = fetchThreadCtxDetails(processHandle, hThread, cDetails);
	if (!pesieve::is_thread_running(hThread)) {
		my_report->status = SCAN_NOT_SUSPICIOUS;
		return false;
	}
	if (!is_ok) {
		// could not fetch the thread context and information
		my_report->status = SCAN_ERROR;
		return false;
	}
	my_report->frames_count = cDetails.stackFramesCount;
	bool isModified = false;
	bool is_unnamed = !isAddrInNamedModule(cDetails.rip);
	if (is_unnamed) {
		my_report->indicators.insert(THI_SUS_IP);
		if (reportSuspiciousAddr(my_report, cDetails.rip)) {
			isModified = true;
		}
	}

	// fill in the info about each candidate:
	for (auto itr = cDetails.shcCandidates.begin(); itr != cDetails.shcCandidates.end(); ++itr) {
		const ULONGLONG addr = *itr;
#ifdef _SHOW_THREAD_INFO
		std::cout << "Checking shc candidate: " << std::hex << addr << "\n";
#endif //_SHOW_THREAD_INFO
		if (reportSuspiciousAddr(my_report, addr)) {
			std::cout << "[@]" << std::dec << tid << " : " << "Suspicious, possible shc: " << std::hex << addr << std::endl;
#ifdef _SHOW_THREAD_INFO
			std::cout << "Found! " << std::hex << addr << "\n";
#endif //_SHOW_THREAD_INFO
			isModified = true;
		}
	}

	const bool hasEmptyGUI = has_empty_gui_info(tid);

	if (this->info.is_extended && info.ext.state == Waiting && !cDetails.is_ret_in_frame)
	{
		is_unnamed = !isAddrInNamedModule(cDetails.ret_on_stack);
#ifdef _SHOW_THREAD_INFO
		std::cout << "Return addr: " << std::hex << cDetails.ret_on_stack << "\n";
		printResolvedAddr(ret_addr);
#endif //_SHOW_THREAD_INFO
		if (is_unnamed) {
			isModified = true;
			my_report->indicators.insert(THI_SUS_RET);
			if (!reportSuspiciousAddr(my_report, (ULONGLONG)cDetails.ret_on_stack)) {
				my_report->stack_ptr = cDetails.rsp;
				/*if (my_report->stats.entropy < 1) { // discard, do not dump
					my_report->module = 0;
					my_report->moduleSize = 0;
				}*/
			}
		}
	}

	// other indicators of stack being corrupt:
	
	bool isStackCorrupt = false;

	if (this->info.is_extended && !cDetails.is_managed && !cDetails.is_ret_as_syscall)
	{
		my_report->indicators.insert(THI_SUS_CALLS_INTEGRITY);
		isStackCorrupt = true;
	}

	if (hasEmptyGUI &&
		cDetails.stackFramesCount == 1
		&& this->info.is_extended && info.ext.state == Waiting && info.ext.wait_reason == UserRequest)
	{
		my_report->indicators.insert(THI_SUS_CALLSTACK_CORRUPT);
		isStackCorrupt = true;
	}

	if (isStackCorrupt) {
		my_report->stack_ptr = cDetails.rsp;
	}
	return isModified;
}


ThreadScanReport* pesieve::ThreadScanner::scanRemote()
{
	if (GetCurrentThreadId() == info.tid) {
		return nullptr; // do not scan your own thread
	}
	ThreadScanReport* my_report = new (std::nothrow) ThreadScanReport(info.tid);
	if (!my_report) {
		return nullptr;
	}
#ifdef _SHOW_THREAD_INFO
	printThreadInfo(info);
#endif // _SHOW_THREAD_INFO

	bool is_unnamed = !isAddrInNamedModule(info.start_addr);
	if (is_unnamed) {
		if (reportSuspiciousAddr(my_report, info.start_addr)) {
			if (my_report->status == SCAN_SUSPICIOUS) {
				my_report->indicators.insert(THI_SUS_START);
			}
		}
	}
	if (!should_scan_context(info)) {
		return my_report;
	}
	if (this->info.is_extended) {
		my_report->thread_state = info.ext.state;
		my_report->thread_wait_reason = info.ext.wait_reason;
		my_report->thread_wait_time = info.ext.wait_time;
	}

	// proceed with detailed checks:
	HANDLE hThread = OpenThread(
		THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE,
		FALSE,
		info.tid
	);
	if (!hThread) {
#ifdef _DEBUG
		std::cerr << "[-] Could not OpenThread. Error: " << GetLastError() << std::endl;
#endif
		my_report->status = SCAN_ERROR;
		return my_report;
	}
	scanRemoteThreadCtx(hThread, my_report);
	CloseHandle(hThread);
	if (my_report->indicators.size()) {
		my_report->status = SCAN_SUSPICIOUS;
	}
	return my_report;
}
