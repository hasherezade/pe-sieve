#pragma once
#include <windows.h>

namespace pesieve {
	namespace util {

		struct AutoBuffer
		{
			AutoBuffer() : buf(nullptr), max_size(0), buf_size(0) { }

			~AutoBuffer() {
				if (buf) {
					::free(buf);
					buf = nullptr;
				}
				max_size = 0;
				buf_size = 0;
			}

			BYTE* alloc(size_t _buf_size)
			{
				if (_buf_size > max_size) {
					BYTE* allocated = (BYTE*)::realloc((void*)buf, _buf_size);
					if (!allocated) {
						return nullptr;
					}
					buf = allocated;
					max_size = _buf_size;
				}
				buf_size = _buf_size;
				::memset(buf, 0, max_size);
				return buf;
			}

			BYTE* buf;
			size_t max_size;
			size_t buf_size;
		};

	}; //namespace util
}; //namespace pesieve
