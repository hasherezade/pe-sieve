#include "iat_block.h"
#include <peconv.h>

namespace pesieve {
	size_t get_longest_func_name(std::map<ULONGLONG, std::set<peconv::ExportedFunc>> &addrToFunc)
	{
		size_t max_len = 0;
		std::map<ULONGLONG, std::set<peconv::ExportedFunc>>::iterator itr;
		for (itr = addrToFunc.begin(); itr != addrToFunc.end(); ++itr) {
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
};

//---

bool pesieve::IATThunksSeries::makeCoverage(IN const peconv::ExportsMapper* exportsMap)
{
	delete cov; //delete previous
	cov = new peconv::ImportedDllCoverage(funcAddresses, *exportsMap);
	if (!cov->findCoveringDll()) {
		// DLL not found
		return false;
	}
	size_t covered_count = cov->mapAddressesToFunctions(cov->dllName);
	this->dllFullName = exportsMap->get_dll_fullname(cov->dllName);
	this->covered = (covered_count == this->funcAddresses.size());
	return this->covered;
}

bool pesieve::IATThunksSeries::fillNamesSpace(const BYTE* buf_start, size_t buf_size, DWORD bufRVA, bool is64b)
{
	if (!buf_start || !this->cov) return false;

	if (!this->cov->isMappingComplete()) {
		return false; //TODO: make a workaround for this case
	}

	const size_t longest_name = get_longest_func_name(this->cov->addrToFunc);
	const size_t field_size = is64b ? sizeof(ULONGLONG) : sizeof(DWORD);

	const size_t thunks_count = this->cov->addrToFunc.size();
	const size_t thunks_area_size = (thunks_count * field_size) + field_size;

	size_t names_rva = bufRVA + thunks_area_size;

	//fill thunks:
	BYTE *buf = const_cast<BYTE*>(buf_start);
	const BYTE *buf_end = buf_start + buf_size;
	std::map<ULONGLONG, std::set<peconv::ExportedFunc>>::iterator itr;
	for (itr = this->cov->addrToFunc.begin(); itr != cov->addrToFunc.end() && buf < buf_end; ++itr) {

		std::set<peconv::ExportedFunc> &expSet = itr->second;
		const peconv::ExportedFunc& exp = *(expSet.begin());
		if (is64b) {
			ULONGLONG *val = (ULONGLONG*)buf;
			*val = names_rva;
		}
		else {
			DWORD *val = (DWORD*)buf;
			*val = MASK_TO_DWORD(names_rva);
		}
		//no need to fill names, they will be autofilled during dumping
		buf += field_size;
		names_rva += sizeof(IMAGE_IMPORT_BY_NAME) + longest_name;
	}
	return true;
}

size_t pesieve::IATThunksSeries::sizeOfNamesSpace(bool is64b)
{
	if (!cov) return 0;

	size_t space_size = 0;
	if (!this->cov->isMappingComplete()) {
		return 0; //TODO: make a workaround for this case
	}
	const size_t longest_name = get_longest_func_name(this->cov->addrToFunc);
	const size_t field_size = is64b ? sizeof(ULONGLONG) : sizeof(DWORD);
	std::map<ULONGLONG, std::set<peconv::ExportedFunc>>::iterator itr;
	for (itr = this->cov->addrToFunc.begin(); itr != cov->addrToFunc.end(); ++itr) {
		std::set<peconv::ExportedFunc> &expSet = itr->second;
		const peconv::ExportedFunc& exp = *(expSet.begin());
		space_size += field_size;
		space_size += sizeof(IMAGE_IMPORT_BY_NAME) + longest_name;
	}
	if (space_size > 0) {
		space_size += sizeof(field_size);
	}
	return space_size;
}

std::string pesieve::IATThunksSeries::getDllName()
{
	return this->dllFullName;
}

//---

bool pesieve::IATBlock::makeCoverage(IN const peconv::ExportsMapper* exportsMap)
{
	if (!exportsMap) return false;

	IATThunksSeriesSet::iterator itr;
	std::set<IATThunksSeries*>to_split;

	for (itr = this->thunkSeries.begin(); itr != thunkSeries.end(); ++itr) {
		IATThunksSeries* series = *itr;
		if (!series->makeCoverage(exportsMap)) {
			to_split.insert(series);
		}
	}

	std::set<IATThunksSeries*>::iterator sItr;
	for (sItr = to_split.begin(); sItr != to_split.end(); ++sItr) {
		IATThunksSeries *series = *sItr;
		IATThunksSeriesSet splitted = splitSeries(series, *exportsMap);
		if (!splitted.size()) {
			continue;
		}
#ifdef _DEBUG
		std::cout << "Uncovered series splitted into: " << splitted.size() << " series\n";
#endif
		this->thunkSeries.erase(series);
		this->thunkSeries.insert(splitted.begin(), splitted.end());
		
		delete series; // delete the series that have been splitted
	}

	size_t covered_count = 0;
	for (itr = this->thunkSeries.begin(); itr != thunkSeries.end(); ++itr) {
		IATThunksSeries* series = *itr;
		
		if (series->isCovered() || series ->makeCoverage(exportsMap)) {
			covered_count++;
		}
	}

	isCoverageComplete = (covered_count == this->thunkSeries.size());
	return isCoverageComplete;
}

pesieve::IATThunksSeriesSet pesieve::IATBlock::splitSeries(IN IATThunksSeries* series, IN const peconv::ExportsMapper &exportsMap)
{
	IATThunksSeriesSet splitted;
	if (!series) return splitted;

	std::map<DWORD, ULONGLONG> addresses = series->getRvaToFuncMap();

	IATThunksSeries *new_series = nullptr;
	std::map<DWORD, ULONGLONG>::iterator itr;
	std::string last_dll = "";

	for (itr = addresses.begin(); itr != addresses.end(); ++itr) {
		ULONGLONG func_addr = itr->second;
		DWORD offset = itr->first;
		const peconv::ExportedFunc *func = exportsMap.find_export_by_va(func_addr);
		if (new_series && (!func || func->libName != last_dll)) {
			//close series
			splitted.insert(new_series);
			new_series = nullptr;
			last_dll = "";
		}
		if (!func) continue;

		if (!new_series) {
			new_series = new IATThunksSeries(offset);
			last_dll = func->libName;
#ifdef _DEBUG
			std::cout << std::hex << "addr:  " << offset << " set DLL: " << last_dll << "\n";
#endif
		}
		new_series->insert(offset, func_addr);
	}
	if (new_series) {
		splitted.insert(new_series);
	}
	return splitted;
}

size_t pesieve::IATBlock::maxDllLen()
{
	size_t max_size = 0;
	IATThunksSeriesSet::iterator itr;
	for (itr = this->thunkSeries.begin(); itr != thunkSeries.end(); ++itr) {
		IATThunksSeries* series = *itr;
		size_t curr_size = series->getDllName().length() + 1;
		if (curr_size > max_size) max_size = curr_size;
	}
	return max_size;
}

size_t pesieve::IATBlock::sizeOfDllsSpace()
{
	const size_t max_len = maxDllLen();
	return max_len * (thunkSeries.size() + 1);
}

std::string pesieve::IATBlock::toString()
{
	std::stringstream stream;
	stream << "---\nIAT at: " << std::hex << iatOffset << ", size: " << iatSize << ", thunks: "
		<< countThunks() << ", is_terminated: " << isTerminated << ", in_main: " << isInMain << "\n";

	if (this->importTableOffset) {
		stream << "ImportTable: " << std::hex << importTableOffset << "\n";
	}
	stream << "---\n";
	std::map<ULONGLONG, const peconv::ExportedFunc*>::const_iterator itr;
	for (itr = functions.begin(); itr != functions.end(); ++itr) {
		ULONGLONG offset = itr->first;
		const peconv::ExportedFunc* exp = itr->second;

		stream << std::hex << offset << "," << addrToFunctionVA[offset] << "," << exp->toString() << "\n";
	}
	return stream.str();
}
