#include "patch_analyzer.h"
//---
using namespace pesieve;

template <typename DELTA_T>
ULONGLONG pesieve::PatchAnalyzer::getJmpDestAddr(ULONGLONG currVA, int instrLen, DELTA_T lVal)
{
	int delta = instrLen + int(lVal);
	ULONGLONG addr = currVA + delta;
	return addr;
}

size_t pesieve::PatchAnalyzer::parseShortJmp(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va)
{
	const size_t instr_size = 2;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, instr_size)) {
		return 0;
	}
	BYTE *lval = (BYTE*)((ULONGLONG)patch_ptr + 1);
	ULONGLONG addr = getJmpDestAddr<BYTE>(patch_va, instr_size, (*lval));

	patch.setHookTarget(addr);
	return instr_size;
}

size_t pesieve::PatchAnalyzer::parseJmp(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va)
{
	const size_t instr_size = 5;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, instr_size)) {
		return 0;
	}
	DWORD *lval = (DWORD*)((ULONGLONG) patch_ptr + 1);
	ULONGLONG addr = getJmpDestAddr<DWORD>(patch_va, instr_size, (*lval));

	patch.setHookTarget(addr);
	return instr_size;
}

size_t pesieve::PatchAnalyzer::parseJmpViaAddr(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va)
{
	const size_t instr_size = 6;
	ULONGLONG addr = NULL;

	DWORD *lval = (DWORD*)((ULONGLONG)patch_ptr + 2);
	if (!isModule64bit) { //32bit
		patch.setHookTarget(*lval, false);
	}
	else { //64bit
		ULONGLONG addr = getJmpDestAddr<DWORD>(patch_va, instr_size, (*lval));
		patch.setHookTarget(addr, false);
	}
	return instr_size;
}

size_t pesieve::PatchAnalyzer::parseMovJmp(PatchList::Patch &patch, PBYTE patch_ptr, bool is_long)
{
	size_t mov_instr_len = is_long ? 9 : 5;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, mov_instr_len + 2)) {
		return 0;
	}

	PBYTE jmp_ptr = patch_ptr + mov_instr_len; // next instruction
	if (is64Modifier(*patch_ptr)) {
		patch_ptr++;
		jmp_ptr++;
		mov_instr_len++; // add length of modifier
	}
	
	DWORD reg_id0 = patch_ptr[0] - 0xB8;

	// before call/jmp there can be also the modifier...
	if (is64Modifier(*jmp_ptr)) {
		jmp_ptr++;
		mov_instr_len++; // add length of modifier
	}
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, jmp_ptr, 2)) {
		return 0;
	}
	DWORD reg_id1 = 0;
	if (jmp_ptr[0] == 0xFF && jmp_ptr[1] >= 0xE0 && jmp_ptr[1] <= 0xEF ) { // jmp reg
		//jmp reg
		reg_id1 = jmp_ptr[1] - 0xE0;
	} else if (jmp_ptr[0] == 0xFF && jmp_ptr[1] >= 0xD0 && jmp_ptr[1] <= 0xDF ) { // call reg
		//jmp reg
		reg_id1 = jmp_ptr[1] - 0xD0;
	} else {
#ifdef _DEBUG
		std::cerr << "It is not MOV->JMP" << std::hex << (DWORD)jmp_ptr[0] << std::endl;
#endif
		return NULL;
	}
	//TODO: take into account also modifiers
	if (reg_id1 != reg_id0) {
#ifdef _DEBUG
		std::cerr << "MOV->JMP : reg mismatch" << std::endl;
#endif
		return NULL;
	}
	size_t patch_size = mov_instr_len;
	ULONGLONG addr = NULL;
	if (!is_long) { //32bit
		DWORD *lval = (DWORD*)((ULONGLONG) patch_ptr + 1);
		addr = *lval;
	} else { //64bit
		ULONGLONG *lval = (ULONGLONG*)((ULONGLONG) patch_ptr + 1);
		addr = *lval;
	}
	patch_size += 2; //add jump reg size
	patch.setHookTarget(addr);
#ifdef _DEBUG
	std::cout << "----> Target: " << std::hex << addr << std::endl;
#endif
	return patch_size;
}

size_t pesieve::PatchAnalyzer::parsePushRet(PatchList::Patch &patch, PBYTE patch_ptr)
{
	size_t instr_size = 5;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, instr_size + 1)) {
		return 0;
	}
	PBYTE ret_ptr = patch_ptr + instr_size; // next instruction
	if (ret_ptr[0] != 0xC3) {
		return NULL; // this is not push->ret
	}
	instr_size++;
	DWORD *lval = (DWORD*)((ULONGLONG) patch_ptr + 1);
	patch.setHookTarget(*lval);
	return instr_size;
}

bool pesieve::PatchAnalyzer::is64Modifier(BYTE op)
{
	if (!isModule64bit) return false;
	if (op >= 0x40 && op <= 0x4F) { // modifier
		return true;
	}
	return false;
}

bool pesieve::PatchAnalyzer::isLongModifier(BYTE op)
{
	if (!isModule64bit) return false;
	if (op >= 0x48 && op <= 0x4F) { // modifier
		return true;
	}
	return false;
}

size_t pesieve::PatchAnalyzer::_analyzeHook(PatchList::Patch &patch, PBYTE patch_ptr, ULONGLONG patch_va)
{
	BYTE op = patch_ptr[0];
	if (op == OP_JMP || op == OP_CALL_DWORD) {
		return parseJmp(patch, patch_ptr, patch_va);
	}
	if (op == OP_SHORTJMP) {
		return parseShortJmp(patch, patch_ptr, patch_va);
	}
	if (op == OP_PUSH_DWORD) {
		return parsePushRet(patch, patch_ptr);
	}
	if (op == OP_JMP_VIA_ADDR_B1 && patch_ptr[1] == OP_JMP_VIA_ADDR_B2) {
		return parseJmpViaAddr(patch, patch_ptr, patch_va);
	}

	bool is_long = false;
	if (is64Modifier(op)) { // mov modifier
		if (isLongModifier(op)) {
			is_long = true;
		}
		op = patch_ptr[1];
	}

	if (op >= 0xB8 && op <= 0xBF) { // is mov
		return parseMovJmp(patch, patch_ptr, is_long);
	}
	return 0;
}

size_t pesieve::PatchAnalyzer::_analyzeRelocated(PatchList::Patch &patch, BYTE* patch_ptr)
{
	if (this->relocs.find(patch.startRva) == this->relocs.end()) {
		return 0;
	}
	// This patch is a relocated field
	const size_t fieldSize = (this->moduleData.is64bit()) ? sizeof(ULONGLONG) : sizeof(DWORD);
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, fieldSize)) {
		return 0;
	}
	ULONGLONG field = (this->moduleData.is64bit()) ? *((ULONGLONG*)patch_ptr) : *((DWORD*)patch_ptr);
	patch.setHookTarget(field, true, pesieve::HOOK_ADDR_REPLACEMENT);
	return fieldSize;
}

size_t pesieve::PatchAnalyzer::analyzeOther(PatchList::Patch& patch)
{
	const ULONGLONG patch_va = moduleData.rvaToVa(patch.startRva);
	const size_t patch_offset = patch.startRva - sectionRVA;
	BYTE* patch_ptr = this->patchedCode + patch_offset;
	size_t size = patch.endRva - patch.startRva;

	if (size > 1) {
		bool isPadding = true;
		for (size_t i = 1; i < size; ++i) {
			if (patch_ptr[0] != patch_ptr[i]) {
				isPadding = false;
			}
		}
		if (isPadding) {
			patch.type = PATCH_PADDING;
			patch.paddingVal = patch_ptr[0];
		}
	}
	if (patch_ptr[0] == 0xCC) {
		if (size == 1 || patch.type == PATCH_PADDING) {
			patch.type = PATCH_BREAKPOINT;
		}
	}
	return size;
}

size_t pesieve::PatchAnalyzer::analyzeHook(PatchList::Patch &patch)
{
	const ULONGLONG patch_va = moduleData.rvaToVa(patch.startRva);
	const size_t patch_offset = patch.startRva - sectionRVA;
	BYTE* patch_ptr = this->patchedCode + patch_offset;

	size_t size = _analyzeRelocated(patch, patch_ptr);
	if (size) {
		return size;
	}
	const size_t kMinSize = 3;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, kMinSize)) {
		return 0;
	}
	size = _analyzeHook(patch, patch_ptr, patch_va);
	if (size == 0 && patch_offset > 0) {
		//it may happen that the address of an existing JMP/CALL was replaced
		//try to parse a byte before the patch...
		size = _analyzeHook(patch, patch_ptr -1, patch_va - 1);
		if (size > 0) {
			// subtract the added position:
			size--;
		}
	}
	return size;
}

