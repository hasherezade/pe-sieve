#pragma once

#include <stdio.h>
#include <stdlib.h>

#include <Windows.h>
#include <TlHelp32.h>

#include "peloader\util.h"
#include "peloader\pe_hdrs_helper.h"
#include "peloader\pe_raw_to_virtual.h"
#include "peloader\pe_virtual_to_raw.h"
#include "peloader\relocate.h"

#define HEADER_SIZE 0x800

bool read_module_header(HANDLE processHandle, BYTE *start_addr, size_t mod_size, OUT BYTE* buffer, const size_t buffer_size);

BYTE* get_module_section(HANDLE processHandle, BYTE *start_addr, size_t mod_size, const size_t section_num, OUT size_t &section_size);
void free_module_section(BYTE *section_buffer);

size_t read_pe_from_memory(const HANDLE processHandle, BYTE *start_addr, const size_t mod_size, OUT BYTE* buffer);

bool dump_module(const char *out_path, const HANDLE processHandle, BYTE *start_addr, size_t mod_size);