#pragma once

#include <windows.h>
#include <stdio.h>

#include "pe_virtual_to_raw.h"
#include "util.h"
#include "relocate.h"

bool sections_virtual_to_raw(BYTE* payload, SIZE_T payload_size, OUT BYTE* destAddress, OUT SIZE_T *raw_size_ptr)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }

    IMAGE_FILE_HEADER *fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*) payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    } else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*) payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    if (!validate_ptr(payload, payload_size, payload, hdrsSize)) {
        return false;
    }
    //copy payload's headers:
    memcpy(destAddress, payload, hdrsSize);

    //copy all the sections, one by one:
#ifdef _DEBUG
    printf("Coping sections:\n");
#endif
    SIZE_T raw_end = 0;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr(payload, payload_size, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
           return false;
        }
        LPVOID section_mapped = (BYTE*) payload + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = destAddress + next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;
        raw_end = next_sec->SizeOfRawData + next_sec->PointerToRawData;

        if (next_sec->VirtualAddress + sec_size > payload_size) {
            printf("[!] Virtual section size is out ouf bounds: %lx\n", sec_size);
            sec_size = SIZE_T(payload_size - next_sec->VirtualAddress);
            printf("[!] Truncated to maximal size: %lx\n", sec_size);
        }
        if (next_sec->VirtualAddress > payload_size && sec_size != 0) {
            printf("[-] VirtualAddress of section is out ouf bounds: %lx\n", static_cast<SIZE_T>(next_sec->VirtualAddress));
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > payload_size) {
            printf("[-] Raw section size is out ouf bounds: %lx\n", sec_size);
            return false;
        }
#ifdef _DEBUG
        printf("[+] %s to: %p\n", next_sec->Name, section_raw_ptr);
#endif
        memcpy(section_raw_ptr, section_mapped, sec_size);
    }
    if (raw_end > payload_size) raw_end = payload_size;
    if (raw_size_ptr != NULL) {
        (*raw_size_ptr) = raw_end;
    }
    return true;
}

BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &out_size, bool rebuffer)
{
	BYTE* in_buf = payload;
	if (rebuffer) {
		BYTE* in_buf = (BYTE*) VirtualAlloc(NULL, in_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		memcpy(in_buf, payload, in_size);
	}

    BYTE* out_buf = (BYTE*) VirtualAlloc(NULL, in_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ULONGLONG oldBase = get_image_base(in_buf);
	bool isOk = true;
	if (!relocate_module(in_buf, in_size, loadBase, oldBase)) {
		printf("[!] Failed relocating the module!\n");
		isOk = false;
	}
	SIZE_T raw_size = 0;
	if (isOk) {
		if (!sections_virtual_to_raw(in_buf, in_size, out_buf, &raw_size)) {
			isOk = false;
		}
	}
	if (rebuffer && in_buf != NULL) {
		VirtualFree(in_buf, in_size, MEM_FREE);
		in_buf = NULL;
	}
	if (!isOk) {
		VirtualFree(out_buf, in_size, MEM_FREE);
		out_buf = NULL;
	}
	out_size = raw_size;
	return out_buf;
}