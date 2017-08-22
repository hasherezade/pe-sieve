#pragma once
#include <Windows.h>
#include "pe_hdrs_helper.h"

#include <stdio.h>

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

bool has_relocations(BYTE *pe_buffer);

bool apply_reloc_block(
    BASE_RELOCATION_ENTRY *block, SIZE_T entriesNum, DWORD page, 
    ULONGLONG oldBase, ULONGLONG newBase, 
    PVOID modulePtr, SIZE_T moduleSize, bool is64bit
);

bool apply_relocations(ULONGLONG newBase, ULONGLONG oldBase, PVOID modulePtr, SIZE_T moduleSize);