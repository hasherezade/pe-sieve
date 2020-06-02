#pragma once

#include <windows.h>

namespace pesieve {
	namespace util {

		typedef enum {
			INTEGRITY_UNKNOWN = -1,
			INTEGRITY_LOW = 0,
			INTEGRITY_MEDIUM, //1
			INTEGRITY_HIGH, //2
			INTEGRITY_SYSTEM //3
		} process_integrity_t;

		bool set_debug_privilege();

		process_integrity_t get_integrity_level(HANDLE hProcess);

		bool is_DEP_enabled(HANDLE hProcess);
	};
};
