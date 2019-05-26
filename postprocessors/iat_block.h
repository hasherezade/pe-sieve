#pragma once 

#include <peconv.h>

#include <sstream>
#include <map>

class IATBlock
{
public:
	IATBlock(BYTE* _iat_ptr)
		: iat_ptr(_iat_ptr), iat_size(0), isValid(false)
	{
	}

	bool append(ULONGLONG offset, const peconv::ExportedFunc *exp)
	{
		if (!exp) return false;

		functions[offset] = exp;
		return true;
	}

	std::string toString(std::stringstream stream)
	{
		std::map<ULONGLONG, const peconv::ExportedFunc*>::const_iterator itr;
		for (itr = functions.begin(); itr != functions.end(); itr++) {
			ULONGLONG offset = itr->first;
			const peconv::ExportedFunc* exp = itr->second;
			stream << std::hex << offset << " : " << exp->funcName << std::endl;
		}
		return stream.str();
	}

	bool isValid;

	BYTE* iat_ptr;
	size_t iat_size;

protected:
	std::map<ULONGLONG, const peconv::ExportedFunc*> functions;
};
