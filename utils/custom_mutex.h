#pragma once
#include <peconv.h>

namespace pesieve
{
	namespace util {

		struct Mutex {
		public:
			Mutex()
			{
				InitializeCriticalSection(&cs);
			}

			void Lock()
			{
				EnterCriticalSection(&cs);
			}

			void Unlock()
			{
				LeaveCriticalSection(&cs);
			}

			~Mutex()
			{
				DeleteCriticalSection(&cs);
			}

		private:
			CRITICAL_SECTION cs;
		};

		struct MutexLocker
		{
		public:
			MutexLocker(Mutex& _mutex)
				: mutex(_mutex)
			{
				mutex.Lock();
			}

			~MutexLocker()
			{
				mutex.Unlock();
			}

		private:
			Mutex& mutex;
		};

	}; //namespace util

}; //namespace pesieve