#pragma once

#include <windows.h>
#include <map>

#include <peconv.h>
#include "pe_sieve_types.h"

#include "../pe_buffer.h"
#include "iat_block.h"
#include "../utils/artefacts_util.h"

namespace pesieve {

	class ImportTableBuffer
	{
	public:

		ImportTableBuffer(DWORD _descriptorsRVA)
			: descriptors(nullptr), descriptosCount(0),
			descriptorsRVA(_descriptorsRVA),
			namesRVA(0), namesBuf(nullptr), namesBufSize(0),
			dllsRVA(0), dllsBufSize(0), dllsBuf(nullptr)
		{
		}

		~ImportTableBuffer()
		{
			delete[]descriptors;
			delete[]namesBuf;
			delete[]dllsBuf;
		}

		bool allocDesciptors(size_t descriptors_count)
		{
			descriptors = new(std::nothrow) IMAGE_IMPORT_DESCRIPTOR[descriptors_count];
			if (!descriptors) {
				return false;
			}
			memset(descriptors, 0, descriptors_count);
			size_t size_bytes = sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptors_count;
			memset(descriptors, 0, size_bytes);
			descriptosCount = descriptors_count;
			return true;
		}

		bool allocNamesSpace(DWORD names_rva, size_t names_size)
		{
			delete[]namesBuf;
			this->namesBuf = new(std::nothrow) BYTE[names_size];
			if (!this->namesBuf) {
				this->namesBufSize = 0;
				return false;
			}
			memset(this->namesBuf, 0, names_size);
			this->namesBufSize = names_size;
			this->namesRVA = names_rva;
			return true;
		}

		bool allocDllsSpace(DWORD dlls_rva, size_t dlls_area_size)
		{
			delete[]dllsBuf;
			this->dllsBuf = new(std::nothrow) BYTE[dlls_area_size];
			if (!this->dllsBuf) {
				this->dllsBufSize = 0;
				return false;
			}
			memset(this->dllsBuf, 0, dlls_area_size);
			this->dllsBufSize = dlls_area_size;
			this->dllsRVA = dlls_rva;
			return true;
		}

		size_t getDescriptosCount()
		{
			return descriptosCount;
		}

		size_t getDescriptorsSize()
		{
			if (!descriptors) return 0;
			const size_t size_bytes = sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptosCount;
			return size_bytes;
		}

		size_t getNamesSize()
		{
			if (!this->namesBuf) return 0;
			return this->namesBufSize;
		}

		size_t getDllNamesSize()
		{
			return dllsBufSize;
		}

		DWORD getRVA()
		{
			return descriptorsRVA;
		}

		//copy table to the Virtual PE buffer
		bool setTableInPe(BYTE *vBuf, size_t vBufSize)
		{
			if (!descriptors || !namesBuf || !dllsBuf) {
				return false;
			}
			const size_t descriptors_size_b = getDescriptorsSize();
			if ((descriptorsRVA + descriptors_size_b) > vBufSize || (namesRVA + namesBufSize) > vBufSize) {
				// buffer too small
				return false;
			}
			IMAGE_DATA_DIRECTORY* imp_dir = peconv::get_directory_entry(vBuf, IMAGE_DIRECTORY_ENTRY_IMPORT, true);
			if (!imp_dir) {
				//cannot retrieve import directory
				return false;
			}

			const size_t import_table_size = getDescriptorsSize() + getNamesSize();

			//copy buffers into PE:
			memcpy(vBuf + descriptorsRVA, descriptors, descriptors_size_b);
			memcpy(vBuf + namesRVA, namesBuf, namesBufSize);
			memcpy(vBuf + dllsRVA, dllsBuf, dllsBufSize);

			//overwrite the Data Directory:
			imp_dir->VirtualAddress = descriptorsRVA;
			imp_dir->Size = MASK_TO_DWORD(import_table_size);
			return true;
		}

	protected:

		BYTE * getNamesSpaceAt(const DWORD rva, size_t required_size);

		BYTE* getDllSpaceAt(const DWORD rva, size_t required_size);

		IMAGE_IMPORT_DESCRIPTOR* descriptors;
		friend class ImpReconstructor;

	private:

		DWORD descriptorsRVA;
		size_t descriptosCount;

		DWORD namesRVA;
		BYTE* namesBuf;
		size_t namesBufSize;

		DWORD dllsRVA;
		BYTE* dllsBuf;
		size_t dllsBufSize;
	};

	class ImpReconstructor {

	public:

		ImpReconstructor(PeBuffer &_peBuffer)
			: peBuffer(_peBuffer), is64bit(false)
		{
			if (!peBuffer.vBuf) return;
			if (peBuffer.isValidPe()) {
				this->is64bit = peconv::is64bit(peBuffer.vBuf);
			}
			else {
				const size_t found_pattern = pesieve::util::is_64bit_code(peBuffer.vBuf, peBuffer.vBufSize);
				this->is64bit = (found_pattern != PATTERN_NOT_FOUND);
			}
			collectMainIatData();
		}

		~ImpReconstructor()
		{
			deleteFoundIATs();
		}

		typedef enum imprec_filter {
			IMP_REC0,
			IMP_REC1,
			IMP_REC2,
			IMP_REC_COUNT
		} t_imprec_filter;

		typedef enum imprec_res {
			IMP_NOT_FOUND = -3,
			IMP_RECOVERY_ERROR = -2,
			IMP_RECOVERY_NOT_APPLICABLE = -1,
			IMP_RECOVERY_SKIPPED = 0,
			IMP_ALREADY_OK = 1,
			IMP_DIR_FIXED = 2,
			IMP_FIXED = 3,
			IMP_RECREATED_FILTER0 = 4,
			IMP_RECREATED_FILTER1 = 5,
			IMP_RECREATED_FILTER2 = 6,
		} t_imprec_res;

		t_imprec_res rebuildImportTable(const IN peconv::ExportsMapper* exportsMap, IN const pesieve::t_imprec_mode &imprec_mode);

		bool printFoundIATs(std::string reportPath);

	private:

		t_imprec_res _recreateImportTableFiltered(const IN peconv::ExportsMapper* exportsMap, IN const pesieve::t_imprec_mode& imprec_mode);

		IATBlock* findIATBlock(IN const peconv::ExportsMapper* exportsMap, size_t start_offset);
		IATBlock* findIAT(IN const peconv::ExportsMapper* exportsMap, size_t start_offset);
		void collectMainIatData();

		//!  has a dynamic IAT in addition to the basic one (that is set in Data Directory)
		bool hasDynamicIAT() const;

		size_t getMainIATSize() const;

		size_t getMaxDynamicIATSize(IN bool isIatTerminated) const;

		bool findImportTable(IN const peconv::ExportsMapper* exportsMap);
		size_t collectIATs(IN const peconv::ExportsMapper* exportsMap);

		bool isDefaultImportValid(IN const peconv::ExportsMapper* exportsMap);

		bool findIATsCoverage(IN const peconv::ExportsMapper* exportsMap, t_imprec_filter filter);
		ImportTableBuffer* constructImportTable();
		bool appendImportTable(ImportTableBuffer &importTable);

		bool appendFoundIAT(DWORD iat_offset, IATBlock* found_block)
		{
			if (foundIATs.find(iat_offset) != foundIATs.end()) {
				return false; //already exist
			}
			foundIATs[iat_offset] = found_block;
			return true;
		}

		void deleteFoundIATs()
		{
			std::map<DWORD, IATBlock*>::iterator itr;
			for (itr = foundIATs.begin(); itr != foundIATs.end(); ++itr) {
				delete itr->second;
			}
			foundIATs.clear();
		}

		PeBuffer &peBuffer;
		bool is64bit;
		std::map<DWORD, IATBlock*> foundIATs;

		std::set<DWORD> mainIatThunks; //< RVAs of the Thunks of the main IAT
	};

}; // namespace pesieve
