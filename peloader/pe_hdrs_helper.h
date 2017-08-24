#pragma once

#include <Windows.h>
#include "util.h"

BYTE* get_nt_hrds(const BYTE *pe_buffer);
IMAGE_NT_HEADERS32* get_nt_hrds32(const BYTE *pe_buffer);
IMAGE_NT_HEADERS64* get_nt_hrds64(const BYTE *pe_buffer);

IMAGE_DATA_DIRECTORY* get_pe_directory(const BYTE* pe_buffer, DWORD dir_id);
bool is64bit(const BYTE *pe_buffer);
ULONGLONG get_module_base(const BYTE *pe_buffer);

size_t get_sections_count(const BYTE* buffer, const size_t buffer_size);
PIMAGE_SECTION_HEADER get_section_hdr(const BYTE* buffer, const size_t buffer_size, size_t section_num);
