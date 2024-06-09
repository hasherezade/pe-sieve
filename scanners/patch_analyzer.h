#pragma once

#include "module_data.h"
#include "patch_list.h"

namespace pesieve {

	//! A postprocessor of the detected code patches. Detects if the patch is a hook, and if so, tries to indentify the address where it leads to.
	class PatchAnalyzer
	{
	public:
		typedef enum {
			OP_SHORTJMP = 0xEB,
			OP_JMP = 0xE9,
			OP_CALL_DWORD = 0xE8,
			OP_PUSH_DWORD = 0x68,
			OP_JMP_VIA_ADDR_B1 = 0xFF,
			OP_JMP_VIA_ADDR_B2 = 0x25
		} t_hook_opcode;

		PatchAnalyzer(ModuleData &_moduleData, DWORD _sectionRVA, PBYTE patched_code, size_t code_size)
			: moduleData(_moduleData), sectionRVA(_sectionRVA), patchedCode(patched_code), codeSize(code_size)
		{
			isModule64bit = moduleData.is64bit();
			moduleData.loadRelocatedFields(relocs);
		}

		size_t analyzeHook(PatchList::Patch &patch);

		size_t analyzeOther(PatchList::Patch& patch);

	protected:
		size_t _analyzeHook(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va);
		size_t _analyzeRelocated(PatchList::Patch &patch, BYTE* patch_ptr);

		size_t parseJmpViaAddr(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va);
		size_t parseShortJmp(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va);
		size_t parseJmp(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va);
		size_t parseMovJmp(PatchList::Patch &patch, PBYTE patch_ptr, bool is_long);
		size_t parsePushRet(PatchList::Patch &patch, PBYTE patch_ptr);

		template <typename DELTA_T>
		ULONGLONG getJmpDestAddr(ULONGLONG currVA, int instrLen, DELTA_T lVal);

		bool is64Modifier(BYTE op);
		bool isLongModifier(BYTE op);

		bool isModule64bit;

		ModuleData &moduleData;
		DWORD sectionRVA;
		PBYTE patchedCode;
		size_t codeSize;

		std::set<DWORD> relocs;
	};

}; //namespace pesieve

