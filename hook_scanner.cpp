#include "hook_scanner.h"

bool clear_iat(PIMAGE_SECTION_HEADER section_hdr, BYTE* original_module, BYTE* loaded_code)
{
	BYTE *orig_code = original_module + section_hdr->VirtualAddress;
	IMAGE_DATA_DIRECTORY* iat_dir = get_pe_directory(original_module, 12); //GET_IAT
	if (!iat_dir) {
		return false;
	}
	DWORD iat_rva = iat_dir->VirtualAddress;
	DWORD iat_size = iat_dir->Size;
	DWORD iat_end = iat_rva + iat_size;

	if (
		(iat_rva >= section_hdr->VirtualAddress && (iat_rva < (section_hdr->VirtualAddress + section_hdr->SizeOfRawData)))
		|| (iat_end >= section_hdr->VirtualAddress && (iat_end < (section_hdr->VirtualAddress + section_hdr->SizeOfRawData)))
	)
	{
#ifdef _DEBUG
		printf("IAT is in Code section!\n");
#endif
		DWORD offset = iat_rva - section_hdr->VirtualAddress;
		memset(orig_code + offset, 0, iat_size);
		memset(loaded_code + offset, 0, iat_size);
	}
	return true;
}

size_t report_patches(const char* file_name, DWORD rva, BYTE *orig_code, BYTE *patched_code, size_t code_size)
{
	const char delimiter = ';';
	FILE *f1 = fopen(file_name, "wb");
	size_t patches_count = 0;

	bool patch_flag = false;
	for (size_t i = 0; i < code_size; i++) {
		if (orig_code[i] == patched_code[i]) {
			patch_flag = false;
			continue;
		}
		if (patch_flag == false) {
			patch_flag = true;
			if (f1) {
				fprintf(f1, "%8.8X%cpatch_%d\n", rva + i, delimiter, patches_count);
			} else {
				printf("%8.8X\n", rva + i);
			}
			patches_count++;
		}
	}
	if (f1) fclose(f1);
	return patches_count;
}

t_scan_status is_module_hooked(HANDLE processHandle, MODULEENTRY32 &module_entry, BYTE* original_module, size_t module_size, char* directory)
{
	//get the code section from the module:
	size_t read_size = 0;
	BYTE *loaded_code = get_module_section(processHandle, module_entry.modBaseAddr, module_entry.modBaseSize, 0, read_size);
	if (loaded_code == NULL) return SCAN_ERROR;

	ULONGLONG original_base = get_image_base(original_module);
	ULONGLONG new_base = (ULONGLONG) module_entry.modBaseAddr;
	if (!apply_relocations(new_base, original_base, original_module, module_size)) {
		printf("reloc failed!\n");
	}

	PIMAGE_SECTION_HEADER section_hdr = get_section_hdr(original_module, module_size, 0);
	BYTE *orig_code = original_module + section_hdr->VirtualAddress;
		
	clear_iat(section_hdr, original_module, loaded_code);
		
	size_t smaller_size = section_hdr->SizeOfRawData > read_size ? read_size : section_hdr->SizeOfRawData;
#ifdef _DEBUG
	printf("Code RVA: %x to %x\n", section_hdr->VirtualAddress, section_hdr->SizeOfRawData);
#endif
	//check if the code of the loaded module is same as the code of the module on the disk:
	int res = memcmp(loaded_code, orig_code, smaller_size);
	if (res != 0) {
		char mod_name[MAX_PATH] = { 0 };
		sprintf(mod_name, "%s\\%llX.dll.tag", directory, (ULONGLONG)module_entry.modBaseAddr);
		size_t patches_count = report_patches(mod_name, section_hdr->VirtualAddress, orig_code, loaded_code, smaller_size);
		if (patches_count) {
			printf("Total patches: %d\n", patches_count);
		}
		sprintf(mod_name, "%s\\%llX.dll", directory, (ULONGLONG)module_entry.modBaseAddr);
		if (!dump_module(mod_name, processHandle, module_entry.modBaseAddr, module_entry.modBaseSize)) {
			printf("Failed dumping module!\n");
		}
	}
	free_module_section(loaded_code);
	loaded_code = NULL;

	if (res != 0) {
		return SCAN_MODIFIED; // modified
	}
	return SCAN_NOT_MODIFIED; //not modified
}