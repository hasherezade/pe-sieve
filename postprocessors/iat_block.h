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

	bool makeCoverage(IN peconv::ExportsMapper* exportsMap)
	{
		delete cov; //delete previous
		cov = new peconv::ImportedDllCoverage(funcAddresses, *exportsMap);
		if (!cov->findCoveringDll()) {
			// DLL not found
			return false;
		}
		size_t covered = cov->mapAddressesToFunctions(cov->dllName);
		return covered == this->funcAddresses.size();
	}

	static size_t getLongestFuncName(std::map<ULONGLONG, std::set<peconv::ExportedFunc>> &addrToFunc)
	{
		size_t max_len = 0;
		std::map<ULONGLONG, std::set<peconv::ExportedFunc>>::iterator itr;
		for (itr = addrToFunc.begin(); itr != addrToFunc.end(); itr++) {
			std::set<peconv::ExportedFunc> &expSet = itr->second;
			const peconv::ExportedFunc& exp = *(expSet.begin());
			if (exp.isByOrdinal) {
				continue;
			}
			if (exp.funcName.length() > max_len) {
				max_len = exp.funcName.length();
			}
		}
		return max_len;
	}

	size_t sizeOfNamesSpace(bool is64b)
	{
		size_t space_size = 0;
		if (!this->cov->isMappingComplete()) {
			return 0; //TODO: make a workaround for this case
		}
		const size_t longest_name = getLongestFuncName(this->cov->addrToFunc);
		const size_t field_size = is64b ? sizeof(ULONGLONG) : sizeof(DWORD);
		std::map<ULONGLONG, std::set<peconv::ExportedFunc>>::iterator itr;
		for (itr = this->cov->addrToFunc.begin(); itr != cov->addrToFunc.end(); itr++) {
			std::set<peconv::ExportedFunc> &expSet = itr->second;
			const peconv::ExportedFunc& exp = *(expSet.begin());
			space_size += field_size;
			if (!exp.isByOrdinal) {
				space_size += sizeof(IMAGE_IMPORT_BY_NAME) + longest_name;
			}
		}
		if (space_size > 0) {
			space_size += sizeof(field_size);
		}
		return space_size;
	}

	bool fillNamesSpace(const BYTE* buf_start, size_t buf_size, DWORD bufRVA, bool is64b)
	{
		if (!buf_start) return false;

		if (!this->cov->isMappingComplete()) {
			return false; //TODO: make a workaround for this case
		}
		
		const size_t longest_name = getLongestFuncName(this->cov->addrToFunc);
		const size_t field_size = is64b ? sizeof(ULONGLONG) : sizeof(DWORD);

		const size_t thunks_count = this->cov->addrToFunc.size();
		const size_t thunks_area_size = (thunks_count * field_size) + field_size;

		DWORD names_rva = bufRVA + thunks_area_size;

		//fill thunks:
		BYTE *buf = const_cast<BYTE*>(buf_start);
		const BYTE *buf_end = buf_start + buf_size;
		std::map<ULONGLONG, std::set<peconv::ExportedFunc>>::iterator itr;
		for (itr = this->cov->addrToFunc.begin(); itr != cov->addrToFunc.end() && buf < buf_end; itr++) {

			std::set<peconv::ExportedFunc> &expSet = itr->second;
			const peconv::ExportedFunc& exp = *(expSet.begin());
			if (exp.isByOrdinal) {
				if (is64b) {
					ULONGLONG *ord = (ULONGLONG*)buf;
					*ord = exp.funcOrdinal | IMAGE_ORDINAL_FLAG64;
				}
				else {
					DWORD *ord = (DWORD*)buf;
					*ord = exp.funcOrdinal | IMAGE_ORDINAL_FLAG32;
				}
				buf += field_size;
				continue;
			}
			//by name:
			if (is64b) {
				ULONGLONG *val = (ULONGLONG*)buf;
				*val = names_rva;
			}
			else {
				DWORD *val = (DWORD*)buf;
				*val = names_rva;
			}
			buf += field_size;
			names_rva += sizeof(IMAGE_IMPORT_BY_NAME) + longest_name;

			//no need to fill names, they will be autofilled during dumping
		}
		return true;
	}

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

	bool isValid()
	{
		return this->isCovered() && isTerminated;
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

	std::map<ULONGLONG, const peconv::ExportedFunc*> functions; //TODO: this will be deleted or refactored
	std::map<ULONGLONG, ULONGLONG> addrToFunctionVA; //TODO: this will be deleted or refactored

	std::set<IATThunksSeries*> thunkSeries;

	friend class PeReconstructor;
};
