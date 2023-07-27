#pragma once
#include <Windows.h>
#include <iostream>
//#include "Process.h"

#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

typedef PBYTE ALIGNED_BUF;
typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

ALIGNED_BUF read_from_file(IN const TCHAR* path, IN OUT size_t& read_size);
ALIGNED_BUF alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base = NULL);
ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base = NULL);
bool free_pe_buffer(ALIGNED_BUF buffer, size_t buffer_size = 0);
bool free_aligned(ALIGNED_BUF buffer, size_t buffer_size = 0);
BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t& outputSize, bool rebuffer = true);
ULONGLONG get_image_base(const BYTE* pe_buffer);
bool is64bit(const BYTE* pe_buffer);
WORD get_nt_hdr_architecture(const BYTE* pe_buffer);
BYTE* get_nt_hrds(const BYTE* pe_buffer, size_t buffer_size = 0);
bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size);
bool relocate_module(BYTE* modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase = NULL);
bool apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase);
IMAGE_DATA_DIRECTORY* get_directory_entry(const BYTE* pe_buffer, DWORD dir_id);
bool apply_reloc_block(BASE_RELOCATION_ENTRY* block, SIZE_T entriesNum, DWORD page, ULONGLONG oldBase, ULONGLONG newBase, PVOID modulePtr, SIZE_T moduleSize, bool is64bit);
bool update_image_base(BYTE* payload, ULONGLONG destImageBase);
bool sections_virtual_to_raw(BYTE* payload, SIZE_T payload_size, OUT BYTE* destAddress, OUT SIZE_T* raw_size_ptr);
BYTE* load_pe_moduleByte(BYTE* dllRawData, size_t r_size, OUT size_t& v_size, bool executable, bool relocate);
bool has_relocations(BYTE* pe_buffer);
BYTE* pe_raw_to_virtual(const BYTE* rawPeBuffer, size_t rawPeSize, OUT size_t& outputSize, bool executable = true, ULONGLONG desired_base = NULL);
bool sections_raw_to_virtual(const BYTE* payload, SIZE_T destBufferSize, BYTE* destAddress);
bool dump_to_file(OUT const TCHAR* path, IN PBYTE dump_data, IN size_t dump_size);