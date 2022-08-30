#pragma once

#include <windows.h>

namespace pesieve {

	typedef struct _process_details
	{
		_process_details()
			: isReflection(false), isDEP(false) {}

		_process_details(bool _isReflection, bool _isDEP)
			: isReflection(_isReflection), isDEP(_isDEP) {}

		_process_details(const _process_details& other)
		{
			this->isReflection = other.isReflection;
			this->isDEP = other.isDEP;
		}

		bool isReflection;
		bool isDEP;

	} process_details;

}; // namespace pesieve
