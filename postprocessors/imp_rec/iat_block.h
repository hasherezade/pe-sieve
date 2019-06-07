#pragma once 

#include <peconv.h>

#include <sstream>
#include <map>

class IATThunksSeries
{
public:
	IATThunksSeries(ULONGLONG start_offset)
		: startOffset(start_offset), cov(nullptr)
	{
	}

	~IATThunksSeries()
	{
		delete cov;
	}

	bool insert(ULONGLONG funcAddr)
	{
		funcAddresses.insert(funcAddr);
		return true;
	}

	bool makeCoverage(IN peconv::ExportsMapper* exportsMap);

	//calculate the number of bytes required for filling imports names
	size_t sizeOfNamesSpace(bool is64b);

	// fill the buffer with imports thunks and names
	bool fillNamesSpace(const BYTE* buf_start, size_t buf_size, DWORD bufRVA, bool is64b);

	ULONGLONG startOffset;

private:
	std::set<ULONGLONG> funcAddresses;
	peconv::ImportedDllCoverage *cov;
};

class IATBlock
{
public:
	IATBlock(bool _is64bit, DWORD _iat_offset)
		: is64bit(_is64bit),
		iatOffset(_iat_offset), iatSize(0),
		isMain(false), isTerminated(false), isCoverageComplete(false),
		importTableOffset(0)
	{
	}

	~IATBlock()
	{
		deleteThunkSeries();
	}
	
	void appendSeries(IATThunksSeries* series)
	{
		thunkSeries.insert(series);
	}

	bool append(ULONGLONG offset, ULONGLONG functionVA, const peconv::ExportedFunc *exp)
	{
		if (!exp) return false;

		functions[offset] = exp;
		addrToFunctionVA[offset] = functionVA;
		return true;
	}

	bool isCovered()
	{
		return isCoverageComplete;
	}

	bool isValid()
	{
		bool isClean = this->isCovered() && isTerminated;
		bool isSignificant = (this->functions.size() > 2) && this->isCovered();
		return isClean || isSignificant;
	}

	//how many functions the IAT has
	size_t countThunks()
	{
		return functions.size();
	}

	std::string toString();

	void deleteThunkSeries()
	{
		std::set<IATThunksSeries*>::iterator itr;
		for (itr = this->thunkSeries.begin(); itr != thunkSeries.end(); itr++) {
			delete *itr;
		}
		thunkSeries.clear();
	}

	bool makeCoverage(IN peconv::ExportsMapper* exportsMap);

	bool isTerminated; // is the IAT finished by 0
	bool isMain; // is the IAT set in the Data Directory

	DWORD iatOffset;
	size_t iatSize;

	DWORD importTableOffset;

protected:
	bool is64bit;
	bool isCoverageComplete;

	std::map<ULONGLONG, const peconv::ExportedFunc*> functions; //TODO: this will be deleted or refactored
	std::map<ULONGLONG, ULONGLONG> addrToFunctionVA; //TODO: this will be deleted or refactored

	std::set<IATThunksSeries*> thunkSeries;

	friend class ImpReconstructor;
};
