#include "thread_scanner.h"
#include <peconv.h>
#include "mempage_data.h"
#include "../utils/process_util.h"
#include "../utils/ntddk.h"
#include "../stats/stats.h"
#include "../utils/process_symbols.h"
#include "../utils/syscall_extractor.h"
#include "../utils/artefacts_util.h"

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

std::string pesieve::ThreadScanner::choosePreferredFunctionName(const std::string& dbgSymbol, const std::string& manualSymbol)
{
	if (dbgSymbol.empty()) {
		if (manualSymbol.empty()) {
			return "";
		}
		// Give priority to the manual symbol if the debug symbol is empty
		return manualSymbol;
	}
	// Give priority to the manual symbol if it denotes the actual syscall
	if (!SyscallTable::isSyscallFunc(dbgSymbol)) {
		if (SyscallTable::isSyscallFunc(manualSymbol)) {
			return manualSymbol;
		}
	}
	//oterwise use the debug symbol
	return dbgSymbol;
}

bool pesieve::ThreadScanner::checkReturnAddrIntegrity(IN const std::vector<ULONGLONG>& callStack)
{
	if (this->info.last_syscall == INVALID_SYSCALL || !symbols || !callStack.size() || !info.is_extended || !g_SyscallTable.isReady()) {
		return true; // skip the check
	}
	const ULONGLONG lastCalled = *(callStack.begin());
	const std::string debugFuncName = symbols->funcNameFromAddr(lastCalled);
	const std::string manualSymbol = exportsMap ? resolveLowLevelFuncName(lastCalled) : "";
	if (debugFuncName.empty() && !exportsMap) {
		return true; // skip the check
	}
	const std::string lastFuncCalled = choosePreferredFunctionName(debugFuncName, manualSymbol);
	if (lastFuncCalled.empty()) {
#ifdef _DEBUG
		std::cout << "ERR: Can't fetch the name of the last function called!\n";
#endif
		return false;
	}
	if (callStack.size() == 1) {
		if (this->info.ext.wait_reason == Suspended && lastFuncCalled == "RtlUserThreadStart" && this->info.last_syscall == 0) {
			return true; //normal for suspended threads
		}
		return false; // otherwise it is an anomaly
	}
	// Proceed to check if the last syscall matches the last function called...

#ifndef _WIN64
	static bool isWow64 = util::is_current_wow64();
	if (!isWow64 && lastFuncCalled == "KiFastSystemCallRet") {
		return true;
	}
#endif
	const std::string syscallFuncName = g_SyscallTable.getSyscallName(this->info.last_syscall);
	if (syscallFuncName.empty()) {
		return true; // skip the check
	}
	if (SyscallTable::isSameSyscallFunc(syscallFuncName, lastFuncCalled)) {
		return true; // valid
	}
	
	const ScannedModule* mod = modulesInfo.findModuleContaining(lastCalled);
	const std::string lastModName = mod ? mod->getModName() : "";

	if (syscallFuncName == "NtCallbackReturn") {
		if (lastModName == "win32u.dll" 
			|| lastModName == "user32.dll" || lastModName == "winsrv.dll") // for Windows7
		{
			return true;
		}
	}
	if (!SyscallTable::isSyscallDll(lastModName)) {
//#ifdef _DEBUG
		std::cout << "[@]" << std::dec << info.tid << " : " << "LastSyscall: " << syscallFuncName << " VS LastCalledAddr: " << std::hex << lastCalled 
			<< " : " << lastFuncCalled << "(" << lastModName << "." << manualSymbol << " )" << " DIFFERENT!"
			<< " WaitReason: " << std::dec << ThreadScanReport::translate_wait_reason(this->info.ext.wait_reason) << std::endl;
//#endif //_DEBUG
		return false;
	}

	if (this->info.ext.wait_reason == WrUserRequest ||
		this->info.ext.wait_reason == UserRequest)
	{
		if (syscallFuncName.rfind("NtUser", 0) == 0 ) {
			if (lastFuncCalled.rfind("NtUser", 0) == 0) return true;
			if (lastFuncCalled.rfind("NtGdi", 0) == 0) return true;
		}
		if (syscallFuncName.rfind("NtGdi", 0) == 0) {
			if (lastFuncCalled.rfind("NtGdi", 0) == 0) return true;
			if (lastFuncCalled.rfind("NtUser", 0) == 0) return true;
		}
	}

	if (this->info.ext.wait_reason == UserRequest) {
		if (syscallFuncName.find("WaitFor", 0) != std::string::npos &&
			(lastFuncCalled.find("WaitFor", 0) != std::string::npos))
		{
			return true;
		}
		if (syscallFuncName == "NtWaitForSingleObject") {
			if ((lastFuncCalled.rfind("NtQuery", 0) == 0) || lastFuncCalled == "NtDelayExecution") return true;
		}
		if (syscallFuncName.rfind("NtUser", 0) == 0 && lastFuncCalled == "NtWaitForWorkViaWorkerFactory") {
			return true;
		}
		if (syscallFuncName.rfind("NtUserModify", 0) == 0 && lastFuncCalled == "NtDeviceIoControlFile") {
			return true;
		}
	}

	if (this->info.ext.wait_reason == WrQueue) {
		if (syscallFuncName.rfind("NtWaitFor", 0) == 0 && lastFuncCalled == "NtWaitForWorkViaWorkerFactory") {
			return true;
		}
		if (syscallFuncName == "NtWaitForWorkViaWorkerFactory") {
			if (lastFuncCalled.rfind("NtWaitFor", 0) == 0 || lastFuncCalled.rfind("NtUserMsgWaitFor", 0) == 0 || lastFuncCalled.rfind("NtUserCreate", 0) == 0) {
				return true;
			}
		}
	}

	if (this->info.ext.wait_reason == DelayExecution) {
		if (syscallFuncName == "NtDelayExecution") {
			if ((lastFuncCalled.rfind("NtUserMsgWaitFor", 0) == 0) || (lastFuncCalled.rfind("NtWaitFor", 0) == 0)) return true;
		}
	}
//#ifdef _DEBUG
	std::cout << "[@]" << std::dec << info.tid << " : " << "LastSyscall: " << syscallFuncName << " VS LastCalledAddr: " << std::hex << lastCalled
		<< " : " << lastFuncCalled << "(" << lastModName << "." << manualSymbol << " )" << " DIFFERENT!"
		<< " WaitReason: " << std::dec << ThreadScanReport::translate_wait_reason(this->info.ext.wait_reason) << std::endl;
//#endif //_DEBUG
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

size_t pesieve::ThreadScanner::_analyzeCallStack(IN OUT ctx_details& cDetails, OUT IN std::set<ULONGLONG> &shcCandidates)
{
	size_t processedCntr = 0;

	cDetails.is_managed = false;
	cDetails.is_ret_in_frame = false;
#ifdef _SHOW_THREAD_INFO
	std::cout << "\n" << "Stack frame Size: " << std::dec << cDetails.callStack.size() << "\n===\n";
#endif //_SHOW_THREAD_INFO
	for (auto itr = cDetails.callStack.rbegin(); itr != cDetails.callStack.rend() ;++itr, ++processedCntr) {
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
				shcCandidates.insert(next_return);
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

size_t pesieve::ThreadScanner::analyzeCallStackInfo(IN OUT ThreadScanReport& my_report)
{
	const size_t analyzedCount = _analyzeCallStack(my_report.cDetails, my_report.shcCandidates);

	bool checkCalls = true;
	if (my_report.cDetails.is_managed) {
		checkCalls = false;
	}
	if (info.ext.wait_reason > WrQueue ||
		info.ext.wait_reason == WrFreePage || info.ext.wait_reason == WrPageIn || info.ext.wait_reason == WrPoolAllocation ||
		info.ext.wait_reason == FreePage || info.ext.wait_reason == PageIn || info.ext.wait_reason == PoolAllocation ||
		info.ext.wait_reason == Suspended)// there can be last func. vs last syscall mismatch in case of suspended threads
	{
		checkCalls = false; 
	}
	if (checkCalls) {
		my_report.cDetails.is_ret_as_syscall = checkReturnAddrIntegrity(my_report.cDetails.callStack);
	} 
	return analyzedCount;
}

size_t pesieve::ThreadScanner::fillCallStackInfo(IN HANDLE hProcess, IN HANDLE hThread, IN LPVOID ctx, IN OUT ThreadScanReport& my_report)
{
	// do it in a new thread to prevent stucking...
	t_stack_enum_params args(hProcess, hThread, ctx, &my_report.cDetails);

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
	my_report.cDetails.callStack = args.callStack;
	return args.callStack.size();
}

namespace pesieve {
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
}; //namespace pesieve

bool pesieve::ThreadScanner::fetchThreadCtxDetails(IN HANDLE hProcess, IN HANDLE hThread, OUT ThreadScanReport& my_report)
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
			my_report.cDetails.init(false, ctx.Eip, ctx.Esp, ctx.Ebp);
			read_return_ptr<DWORD>(hProcess, my_report.cDetails);
			retrieved = fillCallStackInfo(hProcess, hThread, &ctx, my_report);
		}
	}
#endif
	if (!is_ok) {

		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
		if (GetThreadContext(hThread, &ctx)) {
			is_ok = true;
#ifdef _WIN64
			my_report.cDetails.init(true, ctx.Rip, ctx.Rsp, ctx.Rbp);
			read_return_ptr<ULONGLONG>(hProcess, my_report.cDetails);
#else
			my_report.cDetails.init(false, ctx.Eip, ctx.Esp, ctx.Ebp);
			read_return_ptr<DWORD>(hProcess, my_report.cDetails);
#endif
			retrieved = fillCallStackInfo(hProcess, hThread, &ctx, my_report);
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
	if (!SyscallTable::isSyscallDll(mod->getModName())) {
		// not a DLL containing syscalls
		return "";
	}
	std::string expName;
	for (size_t disp = 0; disp < maxDisp; disp++) {
		const ULONGLONG va = addr - disp;

		const std::set<peconv::ExportedFunc>* exp_set = exportsMap->find_exports_by_va(va);
		if (!exp_set) {
			continue; // no exports at this VA
		}
		// walk through the export candicates, and find the most suitable one:
		for (auto it1 = exp_set->begin(); it1 != exp_set->end(); ++it1) {
			const peconv::ExportedFunc& exp = *it1;
			const std::string libName = exp.libName;
			if (!SyscallTable::isSyscallDll(libName)) {
				// it is not a low-level export
				continue;
			}
			expName = exp.nameToString();
			// give preference to the functions naming syscalls:
			if (SyscallTable::isSyscallFunc(expName)) {
				return expName;
			}
		}
	}
	// otherwise, return any found
	return expName;
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

bool pesieve::ThreadScanner::fillAreaStats(ThreadScanReport* my_report)
{
	if (!my_report) return false;

	ULONG_PTR end_va = (ULONG_PTR)my_report->module + my_report->moduleSize;
	MemPageData mem(this->processHandle, this->isReflection, (ULONG_PTR)my_report->module, end_va);
	if (!mem.fillInfo() || !mem.load()) {
		return false;
	}
	my_report->is_code = util::is_code(mem.loadedData.getData(true), mem.loadedData.getDataSize(true));
	AreaStatsCalculator calc(mem.loadedData);
	return calc.fill(my_report->stats, nullptr);
}

bool pesieve::ThreadScanner::reportSuspiciousAddr(ThreadScanReport* my_report, ULONGLONG susp_addr)
{
	MEMORY_BASIC_INFORMATION page_info = { 0 };
	if (!get_page_details(processHandle, (LPVOID)susp_addr, page_info)) {
		return false;
	}
	if (page_info.State & MEM_FREE) {
		return false;
	}
	ULONGLONG base = (ULONGLONG)page_info.BaseAddress;
	my_report->module = (HMODULE)base;
	my_report->moduleSize = page_info.RegionSize;
	my_report->protection = page_info.AllocationProtect;
	my_report->susp_addr = susp_addr;
	my_report->status = SCAN_SUSPICIOUS;
	const bool isStatFilled = fillAreaStats(my_report);
#ifndef NO_ENTROPY_CHECK
	if (isStatFilled && (my_report->stats.entropy < ENTROPY_TRESHOLD)) {
		my_report->status = SCAN_NOT_SUSPICIOUS;
	}
#endif
	return true;
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

bool pesieve::ThreadScanner::scanRemoteThreadCtx(HANDLE hThread, ThreadScanReport& my_report)
{
	const DWORD tid = info.tid;
	ctx_details &cDetails = my_report.cDetails;

	const bool is_ok = fetchThreadCtxDetails(processHandle, hThread, my_report);
	if (!pesieve::is_thread_running(hThread)) {
		my_report.status = SCAN_NOT_SUSPICIOUS;
		return false;
	}
	if (!is_ok || !analyzeCallStackInfo(my_report)) {
		// could not fetch the thread context and information
		my_report.status = SCAN_ERROR;
		return false;
	}
	
	my_report.stack_ptr = cDetails.rsp;
	bool is_unnamed = !isAddrInNamedModule(cDetails.rip);
	if (is_unnamed) {
		my_report.indicators.insert(THI_SUS_IP);
		if (reportSuspiciousAddr(&my_report, cDetails.rip)) {
			if (my_report.status == SCAN_SUSPICIOUS) {
				my_report.indicators.insert(THI_SUS_CALLSTACK_SHC);
			}
		}
	}

	for (auto itr = my_report.shcCandidates.begin(); itr != my_report.shcCandidates.end(); ++itr) {
		const ULONGLONG addr = *itr;
#ifdef _SHOW_THREAD_INFO
		std::cout << "Checking shc candidate: " << std::hex << addr << "\n";
#endif //_SHOW_THREAD_INFO
		//automatically verifies if the address is legit:
		if (reportSuspiciousAddr(&my_report, addr)) {
			if (my_report.status == SCAN_SUSPICIOUS) {
				my_report.indicators.insert(THI_SUS_CALLSTACK_SHC);
#ifdef _DEBUG
				std::cout << "[@]" << std::dec << tid << " : " << "Suspicious, possible shc: " << std::hex << addr << " Entropy: " << std::dec << my_report.stats.entropy << " : " << my_report.is_code << std::endl;
#endif //_DEBUG
				if (my_report.is_code) {
					break;
				}
#ifdef _SHOW_THREAD_INFO
				std::cout << "Found! " << std::hex << addr << "\n";
#endif //_SHOW_THREAD_INFO
			}
		}
	}

	if (this->info.is_extended && info.ext.state == Waiting && this->info.ext.wait_reason != Suspended 
		&& !cDetails.is_ret_in_frame)
	{
		const ULONGLONG ret_addr = cDetails.ret_on_stack;
		is_unnamed = !isAddrInNamedModule(ret_addr);
#ifdef _SHOW_THREAD_INFO
		std::cout << "Return addr: " << std::hex << ret_addr << "\n";
		printResolvedAddr(ret_addr);
#endif //_SHOW_THREAD_INFO
		if (is_unnamed && reportSuspiciousAddr(&my_report, (ULONGLONG)ret_addr)) {
			my_report.indicators.insert(THI_SUS_RET);
			if (my_report.status == SCAN_SUSPICIOUS) {
				my_report.indicators.insert(THI_SUS_CALLSTACK_SHC);
			}
			else {
				my_report.status = SCAN_SUSPICIOUS;
				if (my_report.stats.entropy < 1) { // discard, do not dump
					my_report.module = 0;
					my_report.moduleSize = 0;
				}
			}
		}
	}

	// other indicators of stack being corrupt:
	
	if (this->info.is_extended && !my_report.cDetails.is_managed && !my_report.cDetails.is_ret_as_syscall)
	{
		my_report.indicators.insert(THI_SUS_CALLS_INTEGRITY);
		my_report.status = SCAN_SUSPICIOUS;
	}

	if (cDetails.callStack.size() == 1
		&& this->info.is_extended && info.ext.state == Waiting && info.ext.wait_reason == UserRequest)
	{
		my_report.indicators.insert(THI_SUS_CALLSTACK_CORRUPT);
		my_report.status = SCAN_SUSPICIOUS;
	}
	return (my_report.status == SCAN_SUSPICIOUS) ? true : false;
}

bool pesieve::ThreadScanner::filterDotNet(ThreadScanReport& my_report)
{
	if (!isManaged) return false;

	const size_t count = my_report.indicators.size();
	if (count > 1) return false;

	auto itr = my_report.indicators.begin();
	if (itr == my_report.indicators.end()) return false;

	if (*itr == THI_SUS_CALLSTACK_SHC) {
		my_report.status = SCAN_NOT_SUSPICIOUS;
		return true;
	}
	return false;
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
	if (this->info.is_extended) {
		my_report->thread_state = info.ext.state;
		my_report->thread_wait_reason = info.ext.wait_reason;
		my_report->thread_wait_time = info.ext.wait_time;
	}
	if (!should_scan_context(info)) {
		return my_report;
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
	scanRemoteThreadCtx(hThread, *my_report);
	CloseHandle(hThread);

	filterDotNet(*my_report);
	return my_report;
}
