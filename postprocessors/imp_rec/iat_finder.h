#pragma once

#include <windows.h>
#include <peconv.h>

#include "iat_block.h"

#ifndef MASK_TO_DWORD
#define MASK_TO_DWORD(val) (val & 0xffffffff)
#endif

namespace pesieve {

	//!  A class containing callbacks for functions: find_iat, fill_iat
	class ThunkFoundCallback
	{
	public:
		ThunkFoundCallback()
		{
		}

		//!  the callback that will be called for each candidate for the imported function VA
		virtual bool shouldProcessVA(ULONGLONG va) = 0;

		//!  the callback that will be called validly resolved import
		virtual bool shouldAcceptExport(ULONGLONG va, const peconv::ExportedFunc &exp) = 0;
	};
	//---

	template <typename FIELD_T>
	size_t fill_iat(BYTE* vBuf, size_t vBufSize, IN const peconv::ExportsMapper* exportsMap, IN OUT IATBlock &iat, IN ThunkFoundCallback *callback)
	{
		if (!vBuf || !exportsMap || !iat.iatOffset) return 0;

		size_t max_check = vBufSize - sizeof(FIELD_T);
		if (max_check < sizeof(FIELD_T)) {
			return 0; //size check failed
		}

		iat.isTerminated = true;
		const peconv::ExportedFunc *exp = nullptr;

		IATThunksSeries *series = nullptr;
		bool is_terminated = true;
		FIELD_T *imp = (FIELD_T*)(iat.iatOffset + (ULONG_PTR)vBuf);
		for (; imp < (FIELD_T*)(vBuf + max_check); imp++) {
			if (*imp == 0) {
				is_terminated = true;
				if (series) {
					iat.appendSeries(series); //add filled series
					series = nullptr;
				}
				continue;
			}

			const FIELD_T imp_va = (*imp);

			if (callback) {
				if (!callback->shouldProcessVA(imp_va)) break;
			}

			//std::cout << "checking: " << std::hex << possible_rva << std::endl;
			const peconv::ExportedFunc *exp = exportsMap->find_export_by_va(imp_va);
			if (!exp) break;

			if (callback) {
				if (!callback->shouldAcceptExport(imp_va, *exp)) break;
			}

			is_terminated = false;
			DWORD offset = MASK_TO_DWORD((BYTE*)imp - vBuf);
			iat.append(offset, imp_va, exp);

			if (!series) series = new IATThunksSeries(offset);
			if (series) {
				series->insert(offset, imp_va);
			}
		}
		if (series) {
			iat.appendSeries(series); //add filled series
			series = nullptr;
		}
		iat.isTerminated = is_terminated;
		if (!exp && iat.iatOffset && iat.countThunks() > 0) {
			BYTE *iat_ptr = (BYTE*)(iat.iatOffset + (ULONG_PTR)vBuf);
			size_t diff = (BYTE*)imp - iat_ptr;
			iat.iatSize = diff;
			return iat.iatSize;
		}
		return 0; // invalid IAT
	}

	template <typename FIELD_T>
	IATBlock* find_iat(BYTE* vBuf, size_t vBufSize, IN const peconv::ExportsMapper* exportsMap, IN size_t search_offset, IN ThunkFoundCallback *callback)
	{
		if (!vBuf || !vBufSize ||  !exportsMap) return nullptr;

		const bool is64bit = (sizeof(FIELD_T) == sizeof(DWORD)) ? false : true;

		size_t max_check = vBufSize - sizeof(FIELD_T);
		if (search_offset > vBufSize || max_check < sizeof(FIELD_T)) {
			return nullptr; //size check failed
		}

		for (BYTE* ptr = vBuf + search_offset; ptr < vBuf + max_check; ptr++) {
			FIELD_T *to_check = (FIELD_T*)ptr;
			if (!peconv::validate_ptr(vBuf, vBufSize, to_check, sizeof(FIELD_T))) break;
			FIELD_T possible_va = (*to_check);
			if (possible_va == 0) continue;

			if (callback) {
				if (!callback->shouldProcessVA(possible_va)) continue;
			}

			//std::cout << "checking: " << std::hex << possible_rva << std::endl;
			const peconv::ExportedFunc *exp = exportsMap->find_export_by_va(possible_va);
			if (!exp) continue;

			if (callback) {
				if (!callback->shouldAcceptExport(possible_va, *exp)) continue;
			}

			DWORD iat_offset = DWORD(ptr - vBuf);
			IATBlock *iat_block = new IATBlock(is64bit, iat_offset);
			//validate IAT:
			size_t _iat_size = fill_iat<FIELD_T>(vBuf, vBufSize, exportsMap, *iat_block, callback);
			if (_iat_size > 0) {
				iat_block->iatSize = _iat_size;
				return iat_block;
			}
			delete iat_block; iat_block = nullptr;
		}
		return nullptr;
	}

}; //namespace pesieve

