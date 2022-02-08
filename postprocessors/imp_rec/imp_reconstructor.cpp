#include "imp_reconstructor.h"

#include "iat_finder.h"
#include "import_table_finder.h"

#include <fstream>

using namespace pesieve;

#define MIN_THUNKS_COUNT 2

namespace pesieve {
	BYTE* get_buffer_space_at(IN BYTE* buffer, IN const size_t buffer_size, IN const DWORD buffer_rva, IN const DWORD required_rva, IN const size_t required_size)
	{
		if (!buffer || buffer_rva > required_rva) return nullptr;
		size_t offset = required_rva - buffer_rva;

		BYTE* req_ptr = offset + buffer;
		if (peconv::validate_ptr(buffer, buffer_size, req_ptr, required_size)) {
			return req_ptr;
		}
		return nullptr;
	}
};

//---

BYTE* pesieve::ImportTableBuffer::getNamesSpaceAt(const DWORD rva, size_t required_size)
{
	return get_buffer_space_at(this->namesBuf, this->namesBufSize, this->namesRVA, rva, required_size);
}

BYTE* pesieve::ImportTableBuffer::getDllSpaceAt(const DWORD rva, size_t required_size)
{
	return get_buffer_space_at(this->dllsBuf, this->dllsBufSize, this->dllsRVA, rva, required_size);
}

//---

bool pesieve::ImpReconstructor::hasDynamicIAT() const
{
	size_t maxSize = getMaxDynamicIATSize(true);
	return (maxSize >= MIN_THUNKS_COUNT);
}

size_t pesieve::ImpReconstructor::getMainIATSize() const
{
	std::map<DWORD, IATBlock*>::const_iterator iats_itr;

	//the main IAT can be in chunks, so join them together...
	size_t totalIatSize = 0;
	for (iats_itr = foundIATs.cbegin(); iats_itr != foundIATs.cend(); ++iats_itr) {
		const IATBlock* iblock = iats_itr->second;
		const size_t currCount = iblock->countThunks();

		if (iblock->isInMain) {
			totalIatSize += currCount;
		}
	}
	return totalIatSize;
}

size_t pesieve::ImpReconstructor::getMaxDynamicIATSize(IN bool isIatTerminated) const
{
	std::map<DWORD, IATBlock*>::const_iterator iats_itr;

	size_t maxIATSize = 0;
	for (iats_itr = foundIATs.cbegin(); iats_itr != foundIATs.cend(); ++iats_itr) {
		const IATBlock* iblock = iats_itr->second;
		const size_t currCount = iblock->countThunks();

		if (!iblock->isInMain // is it a dynamic IAT
			&& (iblock->isTerminated == isIatTerminated))
		{
			if (currCount > maxIATSize) {
				maxIATSize = currCount;
			}
		}
	}
	return maxIATSize;
}

pesieve::ImpReconstructor::t_imprec_res pesieve::ImpReconstructor::_recreateImportTableFiltered(const IN peconv::ExportsMapper* exportsMap, IN const pesieve::t_imprec_mode& imprec_mode)
{
	// convert to filter:

	int filter = IMP_REC0;
	switch (imprec_mode) {
	case PE_IMPREC_REBUILD0:
		filter = IMP_REC0; break;
	case PE_IMPREC_REBUILD1:
		filter = IMP_REC1; break;
	case PE_IMPREC_REBUILD2:
		filter = IMP_REC2; break;
	}

	// in AUTO mode: chose higher filter if the unterminated IAT is bigger than the main IAT, or any terminated:

	if (imprec_mode == PE_IMPREC_AUTO) {

		const size_t untermIATSize = getMaxDynamicIATSize(false);
		if (untermIATSize > MIN_THUNKS_COUNT) {
			const size_t mainIATSize = getMainIATSize();
			const size_t termIATSize = getMaxDynamicIATSize(true);

			if ((untermIATSize > mainIATSize) && (untermIATSize > termIATSize)) {
				filter = IMP_REC1;
			}
		}
	}

	// Try to rebuild ImportTable for module

	while (!findIATsCoverage(exportsMap, (t_imprec_filter)filter)) {
		if (imprec_mode != PE_IMPREC_AUTO) {
			// no autodetect: don't try different modes
			return IMP_RECOVERY_ERROR;
		}
		// try next filter:
		filter++;
		//limit exceeded, quit with error:
		if (filter == IMP_REC_COUNT) {
			return IMP_RECOVERY_ERROR;
		}
	}

	//coverage found, try to rebuild:
	bool isOk = false;
	ImportTableBuffer* impBuf = constructImportTable();
	if (impBuf) {
		if (appendImportTable(*impBuf)) {
			isOk = true;
		}
	}
	delete impBuf;

	if (!isOk) {
		return IMP_RECOVERY_ERROR;
	}
	// convert results:
	switch (filter) {
	case IMP_REC0:
		return IMP_RECREATED_FILTER0;
	case IMP_REC1:
		return IMP_RECREATED_FILTER1;
	case IMP_REC2:
		return IMP_RECREATED_FILTER2;
	}
	return IMP_RECREATED_FILTER0;
}

pesieve::ImpReconstructor::t_imprec_res pesieve::ImpReconstructor::rebuildImportTable(const IN peconv::ExportsMapper* exportsMap, IN const pesieve::t_imprec_mode &imprec_mode)
{
	if (!exportsMap || imprec_mode == pesieve::PE_IMPREC_NONE) {
		return IMP_RECOVERY_SKIPPED;
	}

	if (!collectIATs(exportsMap)) {
		return IMP_NOT_FOUND;
	}

	if (!peBuffer.isValidPe()) {
		// this is possibly a shellcode, stop after collecting the IATs
		return IMP_RECOVERY_NOT_APPLICABLE;
	}
	if (!peconv::is_pe_raw_eq_virtual(peBuffer.vBuf, peBuffer.vBufSize)
		&& peconv::is_pe_raw(peBuffer.vBuf, peBuffer.vBufSize))
	{
		// Do not proceed, the PE is in a raw format
		return IMP_RECOVERY_NOT_APPLICABLE;
	}

	if (imprec_mode == PE_IMPREC_UNERASE || 
		(imprec_mode == PE_IMPREC_AUTO && !this->hasDynamicIAT()))
	{
		const bool is_default_valid = this->isDefaultImportValid(exportsMap);
		if (is_default_valid) {
			// Valid Import Table already set
			return pesieve::ImpReconstructor::IMP_ALREADY_OK;
		}
		if (findImportTable(exportsMap)) {
			// ImportTable found and set:
			return pesieve::ImpReconstructor::IMP_DIR_FIXED;
		}
	}
	const bool isDotnet = peconv::is_dot_net(peBuffer.vBuf, peBuffer.vBufSize);
	if (isDotnet && imprec_mode == PE_IMPREC_AUTO) {
		// Valid Import Table already set
		return pesieve::ImpReconstructor::IMP_ALREADY_OK;
	}

	// Try to rebuild ImportTable for module
	if ((imprec_mode == PE_IMPREC_REBUILD0 || imprec_mode == PE_IMPREC_REBUILD1 || imprec_mode == PE_IMPREC_REBUILD2)
		|| imprec_mode == PE_IMPREC_AUTO)
	{
		return _recreateImportTableFiltered(exportsMap, imprec_mode);
	}
	return IMP_RECOVERY_ERROR;
}

bool pesieve::ImpReconstructor::printFoundIATs(std::string reportPath)
{
	if (!foundIATs.size()) {
		return false;
	}
	std::ofstream report;
	report.open(reportPath);
	if (report.is_open() == false) {
		return false;
	}

	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
		report << itr->second->toString();
	}
	report.close();
	return true;
}

bool pesieve::ImpReconstructor::isDefaultImportValid(IN const peconv::ExportsMapper* exportsMap)
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf || !vBufSize) return false;

	IMAGE_DATA_DIRECTORY *iat_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (!iat_dir) return false;

	IMAGE_DATA_DIRECTORY *imp_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IMPORT, true);
	if (!imp_dir) return false;

	if (imp_dir->VirtualAddress == 0 && imp_dir->Size == 0 
		&& iat_dir->VirtualAddress == 0 && iat_dir->Size == 0)
	{
		// the PE has no Import Table, and no artefacts indicating that it was erased. Probably legit no-import PE.
		return false;
	}

	if (iat_dir->VirtualAddress != 0 && imp_dir->VirtualAddress == 0) {
		// the PE has IAT, but no Import Table. Import Table Address was probably erased.
		return false;
	}

	// verify if the Import Table that is currently set is fine:

	DWORD iat_offset = iat_dir->VirtualAddress;
	IATBlock* iat_block = this->findIATBlock(exportsMap, iat_offset);
	if (!iat_block) {
		//could not find any IAT Block at this IAT offset. The IAT offset may be incorrect.
		return false;
	}
	const size_t start_offset = peconv::get_hdrs_size(vBuf);
	const bool is64bit = peconv::is64bit(vBuf);
	size_t table_size = 0;
	IMAGE_IMPORT_DESCRIPTOR *import_table = find_import_table(
		is64bit,
		vBuf,
		vBufSize,
		exportsMap,
		iat_offset,
		table_size,
		start_offset
	);
	if (!import_table) {
		// could not find Import Table for this IAT offset
		return false;
	}
	// Import Table found and it fits the address that was already set
	DWORD imp_table_offset = DWORD((ULONG_PTR)import_table - (ULONG_PTR)vBuf);
	if (imp_dir->VirtualAddress == imp_table_offset) {
		return true;
	}
	return false;
}

IATBlock* pesieve::ImpReconstructor::findIATBlock(IN const peconv::ExportsMapper* exportsMap, size_t start_offset)
{
	if (!exportsMap) return nullptr;

	// filter calls to the own exports
	class ThunkFilterSelfCallback : public ThunkFoundCallback
	{
	public:
		ThunkFilterSelfCallback(const ULONGLONG mod_start, size_t mod_size)
			: startAddr(mod_start), endAddr(mod_start + mod_size)
		{
		}

		virtual bool shouldProcessVA(ULONGLONG va)
		{
			if (va >= startAddr && va < endAddr) {
				// the address is in the current module: this may be a call to module's own function
				return false;
			}
			return true;
		}

		virtual bool shouldAcceptExport(ULONGLONG va, const peconv::ExportedFunc &exp)
		{
			// accept any
			return true;
		}

	protected:
		const ULONGLONG startAddr;
		const ULONGLONG endAddr;
	};
	//---
	ThunkFilterSelfCallback filter = ThunkFilterSelfCallback(peBuffer.moduleBase, peBuffer.getBufferSize());

	IATBlock* iat_block = nullptr;
	if (this->is64bit) {
		iat_block = find_iat<ULONGLONG>(this->peBuffer.vBuf, this->peBuffer.vBufSize, exportsMap, start_offset, &filter);
	}
	else {
		iat_block = find_iat<DWORD>(this->peBuffer.vBuf, this->peBuffer.vBufSize, exportsMap, start_offset, &filter);
	}
	return iat_block;
}


void pesieve::ImpReconstructor::collectMainIatData()
{
	BYTE* vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf) return;

	if (!peconv::has_valid_import_table(vBuf, vBufSize)) {
		// No import table
		return;
	}
	peconv::collect_thunks(vBuf, vBufSize, mainIatThunks);
}

IATBlock* pesieve::ImpReconstructor::findIAT(IN const peconv::ExportsMapper* exportsMap, size_t start_offset)
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf) return nullptr;

	IATBlock* iat_block = findIATBlock(exportsMap, start_offset);
	if (!iat_block) {
		return nullptr;
	}
	DWORD mainIatRVA = 0;
	DWORD mainIatSize = 0;
	IMAGE_DATA_DIRECTORY* dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (dir) {
		mainIatRVA = dir->VirtualAddress;
		mainIatSize = dir->Size;
	}
	if ( (mainIatRVA != 0 && iat_block->iatOffset >= mainIatRVA && iat_block->iatOffset < (mainIatRVA + mainIatSize) )
		|| mainIatThunks.find(iat_block->iatOffset) != mainIatThunks.end() )
	{
		iat_block->isInMain = true;
	}
	return iat_block;
}

size_t pesieve::ImpReconstructor::collectIATs(IN const peconv::ExportsMapper* exportsMap)
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf) return 0;

	size_t found = 0;
	const size_t pe_hdr_size = peconv::get_hdrs_size(vBuf); //if the buffer is not a valid PE, it will be 0

	for (size_t search_offset = pe_hdr_size; search_offset < vBufSize;) {

		IATBlock *currIAT = findIAT(exportsMap, search_offset);
		if (!currIAT) {
			//can't find any more IAT
			break;
		}
		found++;
		const DWORD iat_offset = currIAT->iatOffset;
		const size_t iat_end = iat_offset + currIAT->iatSize;
		if (!appendFoundIAT(iat_offset, currIAT)) {
			delete currIAT; //this IAT already exist in the map
		}
		// next search should be after thie current IAT:
		if (iat_end <= search_offset) {
			break; //this should never happen
		}
		search_offset = iat_end;
	}
	return found;
}

bool pesieve::ImpReconstructor::findImportTable(IN const peconv::ExportsMapper* exportsMap)
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf) return false;

	IMAGE_DATA_DIRECTORY* imp_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IMPORT, true);
	if (!imp_dir) {
		return false;
	}
	IMAGE_DATA_DIRECTORY *iat_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (!iat_dir) {
		return false;
	}
	IMAGE_IMPORT_DESCRIPTOR* import_table = nullptr;
	size_t table_size = 0;

	const size_t start_offset = peconv::get_hdrs_size(vBuf);
	
	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
		IATBlock *currIAT = itr->second;

		const DWORD iat_offset = currIAT->iatOffset;
#ifdef _DEBUG
		std::cout << "[*] Searching import table for IAT: " << std::hex << iat_offset << ", size: " << currIAT->iatSize << std::endl;
#endif
		bool is64bit = peconv::is64bit(vBuf);
		import_table = find_import_table(
			is64bit,
			vBuf,
			vBufSize,
			exportsMap,
			iat_offset,
			table_size,
			start_offset
		);
		if (import_table) {
			//import table found, set it in the IATBlock:
			currIAT->importTableOffset = DWORD((ULONG_PTR)import_table - (ULONG_PTR)vBuf);
			//overwrite the Data Directory:
			iat_dir->VirtualAddress = iat_offset;
			iat_dir->Size = MASK_TO_DWORD(currIAT->iatSize);
			break;
		}
	}

	if (!import_table) return false;

	DWORD imp_offset = MASK_TO_DWORD((ULONG_PTR)import_table - (ULONG_PTR)vBuf);
	if (imp_dir->VirtualAddress == imp_offset && imp_dir->Size == table_size) {
		//std::cout << "[*] Validated Imports offset!\n";
		return true;
	}
#ifdef _DEBUG
	if (imp_dir->Size == table_size) {
		std::cout << "[*] Validated Imports size!\n";
	}
#endif
	//overwrite the Data Directory:
	imp_dir->VirtualAddress = imp_offset;
	imp_dir->Size = MASK_TO_DWORD(table_size);
	return true;
}

bool pesieve::ImpReconstructor::findIATsCoverage(IN const peconv::ExportsMapper* exportsMap, t_imprec_filter filter)
{
	size_t neededIATs = 0;
	size_t covered = 0;
	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
		IATBlock* iat = itr->second;

		switch (filter) {
		case IMP_REC0:
			if (!iat->isInMain && !iat->isTerminated) {
				continue;
			}
		case IMP_REC1:
			if (!iat->isInMain && !iat->isTerminated && iat->countThunks() < MIN_THUNKS_COUNT) {
				continue;
			}
		}
		neededIATs++;

		if (iat->makeCoverage(exportsMap)) {
			covered++;
		}
		else {
			std::cout << "[-] Failed covering block: " << std::hex << itr->first << " series: " << iat->thunkSeries.size() << "\n";
		}
	}
	if (neededIATs == 0) {
		return false;
	}
	return (covered == neededIATs);
}

ImportTableBuffer* pesieve::ImpReconstructor::constructImportTable()
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf || !vBufSize) return nullptr;

	size_t ready_blocks = 0;
	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
		IATBlock* iat = itr->second;
		if (iat->isValid()) {
			ready_blocks += iat->thunkSeries.size();
		}
	}
	if (ready_blocks == 0) {
		return nullptr;
	}
	const DWORD end_rva = MASK_TO_DWORD(vBufSize);
	ImportTableBuffer *importTableBuffer = new(std::nothrow) ImportTableBuffer(end_rva);
	if (!importTableBuffer) {
		return nullptr;
	}
	importTableBuffer->allocDesciptors(ready_blocks + 1);

	const DWORD names_start_rva = MASK_TO_DWORD(importTableBuffer->getRVA() + importTableBuffer->getDescriptorsSize());
	DWORD orig_thunk_rva = names_start_rva;
	size_t names_space = 0;
	size_t i = 0;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		IATThunksSeriesSet::iterator sItr;
		for (sItr = iat->thunkSeries.begin(); sItr != iat->thunkSeries.end(); ++sItr, ++i) {
			IATThunksSeries *series = *sItr;
			importTableBuffer->descriptors[i].FirstThunk = series->startOffset;
			importTableBuffer->descriptors[i].OriginalFirstThunk = orig_thunk_rva;
			//calculate size for names
			const DWORD names_space_size = MASK_TO_DWORD(series->sizeOfNamesSpace(this->is64bit));
			names_space += names_space_size;
			orig_thunk_rva += names_space_size;
		}
	}
	//fill functions' names:
	importTableBuffer->allocNamesSpace(names_start_rva, names_space);
	const DWORD dlls_rva = MASK_TO_DWORD(names_start_rva + names_space);
	size_t dlls_area_size = 0;
	i = 0;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		IATThunksSeriesSet::iterator sItr;
		for (sItr = iat->thunkSeries.begin(); sItr != iat->thunkSeries.end(); ++sItr++, ++i) {
			IATThunksSeries *series = *sItr;
			DWORD name_rva = importTableBuffer->descriptors[i].OriginalFirstThunk;
			const size_t names_space_size = series->sizeOfNamesSpace(this->is64bit);
			BYTE *buf = importTableBuffer->getNamesSpaceAt(name_rva, names_space_size);
			if (!buf) {
				continue;
			}
			series->fillNamesSpace(buf, names_space_size, name_rva, this->is64bit);
		}
		dlls_area_size += iat->sizeOfDllsSpace();
	}
	//fill DLLs' names:
	importTableBuffer->allocDllsSpace(dlls_rva, dlls_area_size);
	DWORD dll_name_rva = dlls_rva;
	i = 0;
	//TODO: optimize it: write the repeating DLL names only once
	for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		DWORD max_dll_name = MASK_TO_DWORD(iat->maxDllLen());
		IATThunksSeriesSet::iterator sItr;
		for (sItr = iat->thunkSeries.begin(); sItr != iat->thunkSeries.end(); ++sItr, ++i) {
			IATThunksSeries *series = *sItr;
			importTableBuffer->descriptors[i].Name = dll_name_rva;
			BYTE *buf = importTableBuffer->getDllSpaceAt(dll_name_rva, max_dll_name);
			if (buf) {
				//fill the name:
				memcpy(buf, series->getDllName().c_str(), series->getDllName().length() + 1);
			}
			dll_name_rva += max_dll_name;
		}
	}
	return importTableBuffer;
}

bool pesieve::ImpReconstructor::appendImportTable(ImportTableBuffer &importTable)
{
	const size_t import_table_size = importTable.getDescriptorsSize() + importTable.getNamesSize() + importTable.getDllNamesSize();
	const size_t new_size = peBuffer.vBufSize + import_table_size;

	if (!peBuffer.resizeBuffer(new_size)) {
		return false;
	}
	
	const DWORD imports_start_rva = importTable.getRVA();
	peBuffer.resizeLastSection(imports_start_rva + import_table_size);
	return importTable.setTableInPe(peBuffer.vBuf, peBuffer.vBufSize);
}
