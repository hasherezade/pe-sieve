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

	bool insert(ULONGLONG funcAddr)
	{
		funcAddresses.insert(funcAddr);
		return true;
	}

	bool makeCoverage(IN peconv::ExportsMapper* exportsMap)
	{
		if (cov) {
			delete cov; cov = nullptr;
		}
		//std::cout << "Start: " << std::hex << startOffset << "\n";
		cov = new peconv::ImportedDllCoverage(funcAddresses, *exportsMap);
		if (!cov->findCoveringDll()) {
			//std::cout << "DLL NOT found\n";
			return false;
		}
		
		size_t covered = cov->mapAddressesToFunctions(cov->dllName);
		//std::cout << "DLL found: " << cov->dllName << " covered num:" << covered << "\n";
		return covered == this->funcAddresses.size();
	}

	std::set<ULONGLONG> funcAddresses;

	ULONGLONG startOffset;
	size_t size;
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

	//how many functions the IAT has
	size_t countThunks()
	{
		return functions.size();
	}

	std::string toString()
	{
		std::stringstream stream;
		stream << "---\nIAT at: " << std::hex << iatOffset << ", size: " << iatSize << ", thunks: " << countThunks() << ", is_terminated: " << isTerminated << "\n";
		if (this->importTableOffset) {
			stream << "ImportTable: " << std::hex << importTableOffset << "\n";
		}
		stream << "---\n";
		std::map<ULONGLONG, const peconv::ExportedFunc*>::const_iterator itr;
		for (itr = functions.begin(); itr != functions.end(); itr++) {
			ULONGLONG offset = itr->first;
			const peconv::ExportedFunc* exp = itr->second;
			
			stream << std::hex << offset << "," << addrToFunctionVA[offset] << ","<< exp->toString() << "\n";
		}
		return stream.str();
	}

	void deleteThunkSeries()
	{
		std::set<IATThunksSeries*>::iterator itr;
		for (itr = this->thunkSeries.begin(); itr != thunkSeries.end(); itr++) {
			delete *itr;
		}
		thunkSeries.clear();
	}

	bool makeCoverage(IN peconv::ExportsMapper* exportsMap);
	bool isCovered();

	bool isTerminated; // is the IAT finished by 0
	bool isMain; // is the IAT set in the Data Directory

	DWORD iatOffset;
	size_t iatSize;

	DWORD importTableOffset;

protected:
	bool is64bit;
	bool isCoverageComplete;

	std::map<ULONGLONG, const peconv::ExportedFunc*> functions;
	std::map<ULONGLONG, ULONGLONG> addrToFunctionVA;

	std::set<IATThunksSeries*> thunkSeries;

	friend class PeReconstructor;
};
