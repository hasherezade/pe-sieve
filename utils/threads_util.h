#pragma once

#include <windows.h>
#include <map>

#define INVALID_SYSCALL (-1)

namespace pesieve {
	namespace util {

		typedef struct _thread_info_ext
		{
			ULONGLONG sys_start_addr;
			DWORD state;
			DWORD wait_reason;
			DWORD wait_time;

			_thread_info_ext()
			{
				this->sys_start_addr = 0;
				this->state = 0;
				this->wait_reason = 0;
				this->wait_time = 0;
			}

			_thread_info_ext(const _thread_info_ext& other)
			{
				this->sys_start_addr = other.sys_start_addr;
				this->state = other.state;
				this->wait_reason = other.wait_reason;
				this->wait_time = other.wait_time;
			}

		} thread_info_ext;

		typedef struct _thread_info
		{
			DWORD tid;
			ULONGLONG start_addr;
			DWORD last_syscall;
			bool is_extended;
			thread_info_ext ext;

			_thread_info(DWORD _tid = 0)
				: tid(_tid), 
				start_addr(0), last_syscall(INVALID_SYSCALL),
				is_extended(false)
			{
			}
			
			_thread_info(const _thread_info& other)
			{
				this->tid = other.tid;
				this->start_addr = other.start_addr;
				this->last_syscall = other.last_syscall;
				this->is_extended = other.is_extended;
				this->ext = other.ext;
			}

		} thread_info;

		bool query_threads_details(IN OUT std::map<DWORD, thread_info>& threads_info);

		bool fetch_threads_info(IN DWORD pid, OUT std::map<DWORD, thread_info>& threads_info);

		bool fetch_threads_by_snapshot(IN DWORD pid, OUT std::map<DWORD, thread_info>& threads_info);

	}; // namespace util
}; // namespace pesieve
