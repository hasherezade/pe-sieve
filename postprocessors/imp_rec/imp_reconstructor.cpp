#include "imp_reconstructor.h"

#include "iat_finder.h"
#include "import_table_finder.h"

#include <fstream>

using namespace pesieve;


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
//---

BYTE* ImportTableBuffer::getNamesSpaceAt(const DWORD rva, size_t required_size)
{
	return get_buffer_space_at(this->namesBuf, this->namesBufSize, this->namesRVA, rva, required_size);
}

BYTE* ImportTableBuffer::getDllSpaceAt(const DWORD rva, size_t required_size)
{
	return get_buffer_space_at(this->dllsBuf, this->dllsBufSize, this->dllsRVA, rva, required_size);
}

//---

bool ImpReconstructor::rebuildImportTable(const IN peconv::ExportsMapper* exportsMap, IN const pesieve::t_imprec_mode &imprec_mode)
{
	if (!exportsMap) {
		return false;
	}
	if (!collectIATs(exportsMap)) {
		return false;
	}
	if (!peBuffer.isValidPe()) {
		// this is possibly a shellcode, stop after collecting the IATs
		return false;
	}
	if (peconv::is_pe_raw(peBuffer.vBuf, peBuffer.vBufSize)) {
		std::cout << "[-] ImportTable NOT recovered: the PE is in a raw format!\n";
		return false;
	}

	bool imp_recovered = false;
	if (imprec_mode == PE_IMPREC_UNERASE || imprec_mode == PE_IMPREC_AUTO) {
		std::cout << "[*] Trying to find ImportTable for module: " << std::hex << (ULONGLONG)peBuffer.moduleBase << "\n";
		bool is_valid = this->isDefaultImportValid(exportsMap);
		if (is_valid) {
			std::cout << "[+] Valid Import Table already set.\n";
			return is_valid;
		}
		imp_recovered = findImportTable(exportsMap);
		if (imp_recovered) {
			std::cout << "[+] ImportTable found.\n";
			return imp_recovered;
		}
		else {
			std::cout << "[-] ImportTable NOT found.\n";
		}
	}

	if (imprec_mode == PE_IMPREC_REBUILD || imprec_mode == PE_IMPREC_AUTO) {
		std::cout << "[*] Trying to rebuild ImportTable for module: " << std::hex << (ULONGLONG)peBuffer.moduleBase << "\n";
		if (findIATsCoverage(exportsMap)) {
			
			ImportTableBuffer *impBuf = constructImportTable();
			if (impBuf) {
				imp_recovered = appendImportTable(*impBuf);
			}
			delete impBuf; impBuf = nullptr;
			if (imp_recovered) {
				std::cout << "[+] ImportTable rebuilt.\n";
			}
		}
		if (!imp_recovered) {
			std::cout << "[-] ImportTable NOT rebuilt.\n";
		}
	}
	return imp_recovered;
}

void ImpReconstructor::printFoundIATs(std::string reportPath)
{
	if (!foundIATs.size()) {
		return;
	}
	std::ofstream report;
	report.open(reportPath);
	if (report.is_open() == false) {
		return;
	}

	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		report << itr->second->toString();
	}
	report.close();
}

bool ImpReconstructor::isDefaultImportValid(IN const peconv::ExportsMapper* exportsMap)
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf) return false;

	IMAGE_DATA_DIRECTORY *iat_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (!iat_dir) return false;

	IMAGE_DATA_DIRECTORY *imp_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IMPORT, true);
	if (!imp_dir) return false;

	DWORD iat_offset = iat_dir->VirtualAddress;
	IATBlock* iat_block = find_iat_block(is64bit, vBuf, vBufSize, exportsMap, iat_offset);
	if (!iat_block) {
		return false;
	}
	const size_t start_offset = peconv::get_hdrs_size(vBuf);
	bool is64bit = peconv::is64bit(vBuf);
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
	DWORD imp_table_offset = DWORD((ULONG_PTR)import_table - (ULONG_PTR)vBuf);
	if (imp_dir->VirtualAddress == imp_table_offset) {
		return true;
	}
	return false;
}

IATBlock* ImpReconstructor::findIAT(IN const peconv::ExportsMapper* exportsMap, size_t start_offset)
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf) return nullptr;

	IATBlock* iat_block = find_iat_block(is64bit, vBuf, vBufSize, exportsMap, start_offset);;
	if (!iat_block) {
		return nullptr;
	}
	size_t iat_size = iat_block->iatSize;
	IMAGE_DATA_DIRECTORY *dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IAT, true);
	if (dir) {
		if (iat_block->iatOffset == dir->VirtualAddress && iat_size == dir->Size) {
			iat_block->isMain = true;
		}
	}
	return iat_block;
}

size_t ImpReconstructor::collectIATs(IN const peconv::ExportsMapper* exportsMap)
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

bool ImpReconstructor::findImportTable(IN const peconv::ExportsMapper* exportsMap)
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
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock *currIAT = itr->second;

		const DWORD iat_offset = currIAT->iatOffset;
		const size_t iat_end = iat_offset + currIAT->iatSize;
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
			iat_dir->Size = currIAT->iatSize;
			break;
		}
	}

	if (!import_table) return false;

	DWORD imp_offset = (BYTE*)import_table - vBuf;
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
	imp_dir->Size = table_size;
	return true;
}

bool ImpReconstructor::findIATsCoverage(IN const peconv::ExportsMapper* exportsMap)
{
	size_t covered = 0;
	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock* iat = itr->second;
		if (iat->makeCoverage(exportsMap)) {
			covered++;
		}
		else {
			std::cout << "[-] Failed covering block: " << std::hex << itr->first << " series: " << iat->thunkSeries.size() << "\n";
		}
	}
	return (covered == foundIATs.size());
}

ImportTableBuffer* ImpReconstructor::constructImportTable()
{
	BYTE *vBuf = this->peBuffer.vBuf;
	const size_t vBufSize = this->peBuffer.vBufSize;
	if (!vBuf) return false;

	size_t ready_blocks = 0;
	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock* iat = itr->second;
		if (iat->isValid()) {
			ready_blocks += iat->thunkSeries.size();
		}
	}
	if (ready_blocks == 0) {
		return nullptr;
	}
	ImportTableBuffer *importTableBuffer = new ImportTableBuffer(vBufSize);
	importTableBuffer->allocDesciptors(ready_blocks + 1);

	const DWORD names_start_rva = importTableBuffer->getRVA() + importTableBuffer->getDescriptorsSize();
	size_t orig_thunk_rva = names_start_rva;
	size_t names_space = 0;
	size_t i = 0;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		IATThunksSeriesSet::iterator sItr;
		for (sItr = iat->thunkSeries.begin(); sItr != iat->thunkSeries.end(); sItr++, i++) {
			IATThunksSeries *series = *sItr;
			importTableBuffer->descriptors[i].FirstThunk = series->startOffset;
			importTableBuffer->descriptors[i].OriginalFirstThunk = orig_thunk_rva;
			//calculate size for names
			const size_t names_space_size = series->sizeOfNamesSpace(this->is64bit);
			names_space += names_space_size;
			orig_thunk_rva += names_space_size;
		}
	}
	//fill functions' names:
	importTableBuffer->allocNamesSpace(names_start_rva, names_space);
	const DWORD dlls_rva = names_start_rva + names_space;
	size_t dlls_area_size = 0;
	i = 0;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		IATThunksSeriesSet::iterator sItr;
		for (sItr = iat->thunkSeries.begin(); sItr != iat->thunkSeries.end(); sItr++, i++) {
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
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		size_t max_dll_name = iat->maxDllLen();
		IATThunksSeriesSet::iterator sItr;
		for (sItr = iat->thunkSeries.begin(); sItr != iat->thunkSeries.end(); sItr++, i++) {
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

bool ImpReconstructor::appendImportTable(ImportTableBuffer &importTable)
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
