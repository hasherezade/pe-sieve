#include "pe_raw_to_virtual.h"
#include "relocate.h"

// Map raw PE into virtual memory of local process:
bool sections_raw_to_virtual(const BYTE* payload, SIZE_T destBufferSize, BYTE* destAddress)
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
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG)&(payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    if (!validate_ptr((const LPVOID) payload, destBufferSize, (const LPVOID) payload, hdrsSize)) {
        return false;
    }
    //copy payload's headers:
    memcpy(destAddress, payload, hdrsSize);

    //copy all the sections, one by one:
    //printf("Coping sections:\n");

    SIZE_T raw_end = 0;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr((const LPVOID) payload, destBufferSize, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
            return false;
        }
        LPVOID section_mapped = destAddress + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = (BYTE*)payload +  next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;
        raw_end = next_sec->SizeOfRawData + next_sec->PointerToRawData;
        
        if (next_sec->VirtualAddress + sec_size > destBufferSize) {
            printf("[!] Virtual section size is out ouf bounds: %lx\n", static_cast<long>(sec_size));
            sec_size = SIZE_T(destBufferSize - next_sec->VirtualAddress);
            printf("[!] Truncated to maximal size: %lx\n", static_cast<long>(sec_size));
        }
        if (next_sec->VirtualAddress >= destBufferSize && sec_size != 0) {
            printf("[-] VirtualAddress of section is out ouf bounds: %lx\n", static_cast<long>(next_sec->VirtualAddress));
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > destBufferSize) {
            printf("[-] Raw section size is out ouf bounds: %lx\n", static_cast<long>(sec_size));
            return false;
        }
        //printf("[+] %s to: %p\n", next_sec->Name, section_raw_ptr);
        memcpy(section_mapped, section_raw_ptr, sec_size);
    }
    return true;
}

bool update_image_base(BYTE* payload, PVOID destImageBase)
{
    bool is64b = is64bit(payload);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        return false;
    }
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        payload_nt_hdr64->OptionalHeader.ImageBase = (ULONGLONG)destImageBase;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        payload_nt_hdr32->OptionalHeader.ImageBase = (DWORD)destImageBase;
    }
    return true;
}

BYTE* pe_raw_to_virtual(const BYTE* payload, size_t in_size, size_t &out_size)
{
    bool is64 = is64bit(payload);

    //check payload:
    BYTE* nt_hdr = get_nt_hrds(payload);
    if (nt_hdr == NULL) {
        printf("Invalid payload: %p\n", payload);
        return false;
    }
    ULONGLONG oldImageBase = 0;
    DWORD payloadImageSize = 0;
    ULONGLONG entryPoint = 0;
    if (is64) {
        IMAGE_NT_HEADERS64* payload_nt_hdr = (IMAGE_NT_HEADERS64*)nt_hdr;
        oldImageBase = payload_nt_hdr->OptionalHeader.ImageBase;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
        entryPoint = payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr = (IMAGE_NT_HEADERS32*)nt_hdr;
        oldImageBase = payload_nt_hdr->OptionalHeader.ImageBase;
        payloadImageSize = payload_nt_hdr->OptionalHeader.SizeOfImage;
        entryPoint = payload_nt_hdr->OptionalHeader.AddressOfEntryPoint;
    }

    SIZE_T written = 0;
    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process
    BYTE* localCopyAddress = (BYTE*) VirtualAlloc(NULL, payloadImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (localCopyAddress == NULL) {
        printf("Could not allocate memory in the current process\n");
        return false;
    }
    //printf("Allocated local memory: %p size: %x\n", localCopyAddress, payloadImageSize);

    if (!sections_raw_to_virtual(payload, payloadImageSize, (BYTE*)localCopyAddress)) {
        printf("Could not copy PE file\n");
        return false;
    }
    out_size = payloadImageSize;
    return localCopyAddress;
}

BYTE* load_pe_module(char *filename, OUT size_t &v_size)
{
    HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(file == INVALID_HANDLE_VALUE) {
        return NULL;
    }
    HANDLE mapping  = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!mapping) {
        CloseHandle(file);
        return NULL;
    }
    BYTE *mappedDLL = NULL;
    BYTE *dllRawData = (BYTE*) MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (dllRawData != NULL) {
        size_t r_size = GetFileSize(file, 0);
        mappedDLL = pe_raw_to_virtual(dllRawData, r_size, v_size);
        UnmapViewOfFile(dllRawData);
    }
    CloseHandle(mapping);
    CloseHandle(file);
    return mappedDLL;
}
