#pragma once

#include <windows.h>
#include <vector>

namespace pesieve {
	namespace util {

		typedef struct _thread_info_ext
		{
			ULONGLONG start_addr;
			DWORD state;
			DWORD wait_reason;
			DWORD wait_time;

			_thread_info_ext()
			{
				this->start_addr = 0;
				this->state = 0;
				this->wait_reason = 0;
				this->wait_time = 0;
			}

			_thread_info_ext(const _thread_info_ext& other)
			{
				this->start_addr = other.start_addr;
				this->state = other.state;
				this->wait_reason = other.wait_reason;
				this->wait_time = other.wait_time;
			}

		} thread_info_ext;

		typedef struct _thread_info
		{
			DWORD tid;
			bool is_extended;
			thread_info_ext ext;

			_thread_info()
			{
				this->tid = 0;
				this->is_extended = false;
			}
			
			_thread_info(const _thread_info& other)
			{
				this->tid = other.tid;
				this->is_extended = other.is_extended;
				this->ext = other.ext;
			}

		} thread_info;

		bool fetch_threads_info(DWORD pid, std::vector<thread_info>& threads_info);

		bool fetch_threads_by_snapshot(DWORD pid, std::vector<thread_info>& threads_info);

	}; // namespace util
}; // namespace pesieve
