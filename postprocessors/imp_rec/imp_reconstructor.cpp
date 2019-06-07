#include "imp_reconstructor.h"

#include "iat_finder.h"
#include "import_table_finder.h"

#include <fstream>

bool ImpReconstructor::rebuildImportTable(IN peconv::ExportsMapper* exportsMap, IN const t_pesieve_imprec_mode &imprec_mode)
{
	if (!exportsMap) {
		return false;
	}
	if (!collectIATs(exportsMap)) {
		return false;
	}
	bool imp_recovered = false;
	if (imprec_mode == PE_IMPREC_UNERASE || imprec_mode == PE_IMPREC_AUTO) {
		std::cout << "[*] Trying to find ImportTable for module: " << std::hex << (ULONGLONG)peBuffer->moduleBase << "\n";
		bool imp_recovered = findImportTable(exportsMap);
		if (imp_recovered) {
			std::cout << "[+] ImportTable found.\n";
			return imp_recovered;
		}
	}
	if (imprec_mode == PE_IMPREC_REBUILD || imprec_mode == PE_IMPREC_AUTO) {
		std::cout << "[*] Trying to reconstruct ImportTable for module: " << std::hex << (ULONGLONG)peBuffer->moduleBase << "\n";
		if (findIATsCoverage(exportsMap)) {
			std::cout << "[+] Complete coverage found.\n";

			ImportTableBuffer *impBuf = constructImportTable();
			if (impBuf) {
				appendImportTable(*impBuf);
			}
			delete impBuf;
		}
		imp_recovered = false; //TODO
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

IATBlock* ImpReconstructor::findIAT(IN peconv::ExportsMapper* exportsMap, size_t start_offset)
{
	if (!peBuffer) return nullptr;
	BYTE *vBuf = this->peBuffer->vBuf;
	const size_t vBufSize = this->peBuffer->vBufSize;
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

size_t ImpReconstructor::collectIATs(IN peconv::ExportsMapper* exportsMap)
{
	if (!peBuffer) return 0;
	BYTE *vBuf = this->peBuffer->vBuf;
	const size_t vBufSize = this->peBuffer->vBufSize;
	if (!vBuf) return 0;

	size_t found = 0;
	for (size_t search_offset = 0; search_offset < vBufSize;) {

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

bool ImpReconstructor::findImportTable(IN peconv::ExportsMapper* exportsMap)
{
	if (!peBuffer) return false;
	BYTE *vBuf = this->peBuffer->vBuf;
	const size_t vBufSize = this->peBuffer->vBufSize;
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

	std::map<DWORD, IATBlock*>::iterator itr;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock *currIAT = itr->second;

		const DWORD iat_offset = currIAT->iatOffset;
		const size_t iat_end = iat_offset + currIAT->iatSize;

		std::cout << "[*] Searching import table for IAT: " << std::hex << iat_offset << ", size: " << iat_dir->Size << std::endl;

		bool is64bit = peconv::is64bit(vBuf);
		import_table = find_import_table(
			is64bit,
			vBuf,
			vBufSize,
			exportsMap,
			iat_offset,
			table_size,
			0 //start offset
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

bool ImpReconstructor::findIATsCoverage(IN peconv::ExportsMapper* exportsMap)
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
	if (!peBuffer) return false;
	BYTE *vBuf = this->peBuffer->vBuf;
	const size_t vBufSize = this->peBuffer->vBufSize;
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

	const size_t names_start_rva = importTableBuffer->getRVA() + importTableBuffer->getDescriptorsSize();
	size_t orig_thunk_rva = names_start_rva;
	size_t names_space = 0;
	size_t i = 0;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		std::set<IATThunksSeries*>::iterator sItr;
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
	importTableBuffer->allocNamesSpace(names_start_rva, names_space);
	i = 0;
	for (itr = foundIATs.begin(); itr != foundIATs.end(); itr++) {
		IATBlock* iat = itr->second;
		if (!iat->isValid()) {
			continue;
		}
		std::set<IATThunksSeries*>::iterator sItr;
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
	}
	return importTableBuffer;
}

bool ImpReconstructor::appendImportTable(ImportTableBuffer &importTable)
{
	if (!peBuffer) return false;

	const size_t import_table_size = importTable.getDescriptorsSize() + importTable.getNamesSize();
	const size_t added_size = import_table_size + PAGE_SIZE;
	const size_t new_size = peBuffer->vBufSize + added_size;

	if (!peBuffer->resizeBuffer(new_size)) {
		return false;
	}

	PIMAGE_SECTION_HEADER last_sec = peconv::get_last_section(peBuffer->vBuf, peBuffer->vBufSize, false);
	if (!last_sec) return false;

	peconv::update_image_size(peBuffer->vBuf, peBuffer->vBufSize);
	size_t vdiff = (importTable.getRVA() + added_size) - last_sec->VirtualAddress;
	size_t rdiff = (importTable.getRVA() + import_table_size) - last_sec->VirtualAddress;
	last_sec->Misc.VirtualSize = vdiff;
	last_sec->SizeOfRawData = rdiff;

	IMAGE_DATA_DIRECTORY* imp_dir = peconv::get_directory_entry(peBuffer->vBuf, IMAGE_DIRECTORY_ENTRY_IMPORT, true);
	if (!imp_dir) {
		return false;
	}
	memcpy(peBuffer->vBuf + importTable.getRVA(), importTable.descriptors, importTable.getDescriptorsSize());
	memcpy(peBuffer->vBuf + importTable.namesRVA, importTable.namesBuf, importTable.namesBufSize);

	//overwrite the Data Directory:
	imp_dir->VirtualAddress = importTable.getRVA();
	imp_dir->Size = import_table_size;
	return true;
}
