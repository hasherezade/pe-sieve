#pragma once 

#include <peconv.h>

#include <sstream>
#include <map>
#include <set>

namespace pesieve {

	class IATThunksSeries
	{
	public:
		IATThunksSeries(DWORD start_offset)
			: startOffset(start_offset), cov(nullptr), covered(false)
		{
		}

		~IATThunksSeries()
		{
			delete cov;
		}

		bool operator<(const IATThunksSeries &other) const
		{
			return startOffset < other.startOffset;
		}

		bool insert(DWORD rva, ULONGLONG funcAddr)
		{
			rvaToFuncVA[rva] = funcAddr;
			funcAddresses.insert(funcAddr);
			return true;
		}

		bool makeCoverage(IN const peconv::ExportsMapper* exportsMap);

		bool isCovered()
		{
			return covered;
		}

		std::string getDllName();

		//calculate the number of bytes required for filling imports names
		size_t sizeOfNamesSpace(bool is64b);

		// fill the buffer with imports thunks and names
		bool fillNamesSpace(const BYTE* buf_start, size_t buf_size, DWORD bufRVA, bool is64b);

		std::map<DWORD, ULONGLONG> getRvaToFuncMap()
		{
			return rvaToFuncVA;
		}

		DWORD startOffset;

	private:
		bool covered;
		std::string dllFullName;
		std::set<ULONGLONG> funcAddresses;
		std::map<DWORD, ULONGLONG> rvaToFuncVA;

		peconv::ImportedDllCoverage *cov;
	};

	struct IATThunksSeriesPtrCompare
	{
		bool operator()(const IATThunksSeries* lhs, const IATThunksSeries* rhs) const
		{
			if (!lhs || !rhs) return false;
			return *lhs < *rhs;
		}
	};

	typedef std::set<IATThunksSeries*, IATThunksSeriesPtrCompare> IATThunksSeriesSet;

	class IATBlock
	{
	public:
		IATBlock(bool _is64bit, DWORD _iat_offset)
			: is64bit(_is64bit),
			iatOffset(_iat_offset), iatSize(0),
			isInMain(false), isTerminated(false), isCoverageComplete(false),
			importTableOffset(0)
		{
		}

		~IATBlock()
		{
			deleteThunkSeries();
		}

		bool operator<(const IATBlock &other) const
		{
			return iatOffset < other.iatOffset;
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

		bool isCovered() const
		{
			return isCoverageComplete;
		}

		bool isValid() const
		{
			//allow for every block with complete coverage
			return isCovered();
		}

		//how many functions the IAT has
		size_t countThunks() const
		{
			return functions.size();
		}

		std::string toString();

		void deleteThunkSeries()
		{
			IATThunksSeriesSet::iterator itr;
			for (itr = this->thunkSeries.begin(); itr != thunkSeries.end(); ++itr) {
				delete *itr;
			}
			thunkSeries.clear();
		}

		bool makeCoverage(IN const peconv::ExportsMapper* exportsMap);

		size_t maxDllLen();
		size_t sizeOfDllsSpace();

		bool isTerminated; // is the IAT finished by 0
		bool isInMain; // is the IAT included in the one set in the Data Directory

		DWORD iatOffset;
		size_t iatSize;

		DWORD importTableOffset;

	protected:
		IATThunksSeriesSet splitSeries(IN IATThunksSeries* notCoveredSeries, IN const peconv::ExportsMapper& exportsMap);

		IATThunksSeriesSet thunkSeries;

		bool is64bit;
		bool isCoverageComplete;

		std::map<ULONGLONG, const peconv::ExportedFunc*> functions;
		std::map<ULONGLONG, ULONGLONG> addrToFunctionVA;

		friend class ImpReconstructor;
	};

};
