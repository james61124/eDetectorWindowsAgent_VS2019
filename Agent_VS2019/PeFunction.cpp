#include "PeFunction.h"

ALIGNED_BUF read_from_file(const TCHAR* in_path, size_t& read_size)
{
    HANDLE file = CreateFile(in_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Cannot open the file for reading!" << std::endl;
#endif
        return nullptr;
    }
    size_t r_size = static_cast<size_t>(GetFileSize(file, 0));
    if (read_size != 0 && read_size <= r_size) {
        r_size = read_size;
    }
    PBYTE buffer = alloc_pe_buffer(r_size, PAGE_READWRITE);
    if (buffer == nullptr) {
#ifdef _DEBUG
        std::cerr << "Allocation has failed!" << std::endl;
#endif
        return nullptr;
    }
    DWORD out_size = 0;
    if (!ReadFile(file, buffer, (DWORD)r_size, &out_size, nullptr)) {
#ifdef _DEBUG
        std::cerr << "Reading failed!" << std::endl;
#endif
        free_pe_buffer(buffer, r_size);
        buffer = nullptr;
        read_size = 0;
    }
    else {
        read_size = r_size;
    }
    CloseHandle(file);
    return buffer;
}
ALIGNED_BUF alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    return alloc_aligned(buffer_size, protect, desired_base);
}
ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
{
    PBYTE buf = (PBYTE)VirtualAlloc((LPVOID)desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
    return buf;
}
bool free_pe_buffer(ALIGNED_BUF buffer, size_t buffer_size)
{
    return free_aligned(buffer, buffer_size);
}
bool free_aligned(ALIGNED_BUF buffer, size_t buffer_size)
{
    if (buffer == nullptr) return true;
    if (!VirtualFree(buffer, 0, MEM_RELEASE)) {
#ifdef _DEBUG
        //std::cerr << "Releasing failed" << std::endl;
        printf("Releasing failed");
#endif
        return false;
    }
    return true;
}
BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t& out_size, bool rebuffer)
{
    BYTE* in_buf = payload;
    if (rebuffer) {
        in_buf = (BYTE*)alloc_pe_buffer(in_size, PAGE_READWRITE);
        if (in_buf == NULL) return NULL;
        memcpy(in_buf, payload, in_size);
    }

    BYTE* out_buf = (BYTE*)alloc_pe_buffer(in_size, PAGE_READWRITE);
    ULONGLONG oldBase = get_image_base(in_buf);
    bool isOk = true;
    // from the loadBase go back to the original base
    if (!relocate_module(in_buf, in_size, oldBase, loadBase)) {
        //Failed relocating the module! Changing image base instead...
        if (!update_image_base(in_buf, (ULONGLONG)loadBase)) {
            //std::cerr << "[-] Failed relocating the module!" << std::endl;
            printf("[-] Failed relocating the module!\n");
            isOk = false;
        }
        else {
#ifdef _DEBUG
            //std::cerr << "[!] WARNING: The module could not be relocated, so the ImageBase has been changed instead!" << std::endl;
            printf("[!] WARNING: The module could not be relocated, so the ImageBase has been changed instead!\n");
#endif
        }
    }
    SIZE_T raw_size = 0;
    if (isOk) {
        if (!sections_virtual_to_raw(in_buf, in_size, out_buf, &raw_size)) {
            isOk = false;
        }
    }
    if (rebuffer && in_buf != NULL) {
        free_pe_buffer(in_buf, in_size);
        in_buf = NULL;
    }
    if (!isOk) {
        free_pe_buffer(out_buf, in_size);
        out_buf = NULL;
    }
    out_size = raw_size;
    return out_buf;
}
ULONGLONG get_image_base(const BYTE* pe_buffer)
{
    bool is64b = is64bit(pe_buffer);
    //update image base in the written content:
    BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
    if (payload_nt_hdr == NULL) {
        return 0;
    }
    ULONGLONG img_base = 0;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        img_base = payload_nt_hdr64->OptionalHeader.ImageBase;
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        img_base = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.ImageBase);
    }
    return img_base;
}
bool is64bit(const BYTE* pe_buffer)
{
    WORD arch = get_nt_hdr_architecture(pe_buffer);
    if (arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return true;
    }
    return false;
}
WORD get_nt_hdr_architecture(const BYTE* pe_buffer)
{
    void* ptr = get_nt_hrds(pe_buffer);
    if (ptr == NULL) return 0;

    IMAGE_NT_HEADERS32* inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
    if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return 0;
    }
    return inh->OptionalHeader.Magic;
}
BYTE* get_nt_hrds(const BYTE* pe_buffer, size_t buffer_size)
{
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (buffer_size != 0) {
        if (!validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)idh, sizeof(IMAGE_DOS_HEADER))) {
            return NULL;
        }
    }
    if (IsBadReadPtr(idh, sizeof(IMAGE_DOS_HEADER))) {
        return NULL;
    }
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    const LONG kMaxOffset = 1024;
    LONG pe_offset = idh->e_lfanew;

    if (pe_offset > kMaxOffset) return NULL;

    IMAGE_NT_HEADERS32* inh = (IMAGE_NT_HEADERS32*)(pe_buffer + pe_offset);
    if (buffer_size != 0) {
        if (!validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)inh, sizeof(IMAGE_NT_HEADERS32))) {
            return NULL;
        }
    }
    if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
        return NULL;
    }
    if (inh->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    return (BYTE*)inh;
}
bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size)
{
    if (buffer_bgn == nullptr || field_bgn == nullptr) {
        return false;
    }
    ULONGLONG start = (ULONGLONG)buffer_bgn;
    ULONGLONG end = start + buffer_size;

    ULONGLONG field_end = (ULONGLONG)field_bgn + field_size;

    if ((ULONGLONG)field_bgn < start) {
        return false;
    }
    if (field_end > end) {
        return false;
    }
    return true;
}
bool relocate_module(BYTE* modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
{
    if (modulePtr == NULL) {
        return false;
    }
    if (oldBase == NULL) {
        oldBase = get_image_base(modulePtr);
    }
#ifdef _DEBUG
    printf("New Base: %llx\n", newBase);
    printf("Old Base: %llx\n", oldBase);
#endif
    if (newBase == oldBase) {
#ifdef _DEBUG
        printf("Nothing to relocate! oldBase is the same as the newBase!\n");
#endif
        return true; //nothing to relocate
    }
    if (apply_relocations(modulePtr, moduleSize, newBase, oldBase)) {
        return true;
    }
#ifdef _DEBUG
    printf("Could not relocate the module!\n");
#endif
    return false;
}
bool apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry((const BYTE*)modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) {
#ifdef _DEBUG
        printf("[!] WARNING: no relocation table found!\n");
#endif
        return false;
    }
    if (!validate_ptr(modulePtr, moduleSize, relocDir, sizeof(IMAGE_DATA_DIRECTORY))) {
        return false;
    }
    DWORD maxSize = relocDir->Size;
    DWORD relocAddr = relocDir->VirtualAddress;
    bool is64b = is64bit((BYTE*)modulePtr);

    IMAGE_BASE_RELOCATION* reloc = NULL;

    DWORD parsedSize = 0;
    while (parsedSize < maxSize) {
        reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR)modulePtr);
        if (!validate_ptr(modulePtr, moduleSize, reloc, sizeof(IMAGE_BASE_RELOCATION))) {
            printf("[-] Invalid address of relocations\n");
            return false;
        }
        parsedSize += reloc->SizeOfBlock;

        if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) {
            break;
        }

        size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
        DWORD page = reloc->VirtualAddress;

        BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)reloc + sizeof(DWORD) + sizeof(DWORD));
        if (!validate_ptr(modulePtr, moduleSize, block, sizeof(BASE_RELOCATION_ENTRY))) {
            printf("[-] Invalid address of relocations block\n");
            return false;
        }
        if (apply_reloc_block(block, entriesNum, page, oldBase, newBase, modulePtr, moduleSize, is64b) == false) {
            return false;
        }
    }
    return (parsedSize != 0);
}
IMAGE_DATA_DIRECTORY* get_directory_entry(const BYTE* pe_buffer, DWORD dir_id)
{
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    BYTE* nt_headers = get_nt_hrds((BYTE*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_DATA_DIRECTORY* peDir = NULL;
    if (is64bit((BYTE*)pe_buffer)) {
        IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    else {
        IMAGE_NT_HEADERS32* nt_headers64 = (IMAGE_NT_HEADERS32*)nt_headers;
        peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
    }
    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}
bool apply_reloc_block(BASE_RELOCATION_ENTRY* block, SIZE_T entriesNum, DWORD page, ULONGLONG oldBase, ULONGLONG newBase, PVOID modulePtr, SIZE_T moduleSize, bool is64bit)
{
    BASE_RELOCATION_ENTRY* entry = block;
    SIZE_T i = 0;
    for (i = 0; i < entriesNum; i++) {
        if (!validate_ptr(modulePtr, moduleSize, entry, sizeof(BASE_RELOCATION_ENTRY))) {
            break;
        }
        DWORD offset = entry->Offset;
        DWORD type = entry->Type;
        if (type == 0) {
            break;
        }
        if (type != RELOC_32BIT_FIELD && type != RELOC_64BIT_FIELD) {
            printf("[-] Not supported relocations format at %d: %d\n", (int)i, (int)type);
            return false;
        }
        DWORD reloc_field = page + offset;
        if (reloc_field >= moduleSize) {
            printf("[-] Malformed field: %lx\n", reloc_field);
            return false;
        }
        if (is64bit) {
            ULONGLONG* relocateAddr = (ULONGLONG*)((ULONG_PTR)modulePtr + reloc_field);
            ULONGLONG rva = (*relocateAddr) - oldBase;
            (*relocateAddr) = rva + newBase;
        }
        else {
            DWORD* relocateAddr = (DWORD*)((ULONG_PTR)modulePtr + reloc_field);
            ULONGLONG rva = (*relocateAddr) - oldBase;
            (*relocateAddr) = static_cast<DWORD>(rva + newBase);
        }
        entry = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)entry + sizeof(WORD));
    }
    return true;
}
bool update_image_base(BYTE* payload, ULONGLONG destImageBase)
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
bool sections_virtual_to_raw(BYTE* payload, SIZE_T payload_size, OUT BYTE* destAddress, OUT SIZE_T* raw_size_ptr)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        //std::cerr << "Invalid payload: " << std::hex << (ULONGLONG) payload << std::endl;
        printf("Invalid payload: %x\n", (ULONGLONG)payload);
        return false;
    }

    IMAGE_FILE_HEADER* fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    if (!validate_ptr(payload, payload_size, payload, hdrsSize)) {
        return false;
    }
    //copy payload's headers:
    memcpy(destAddress, payload, hdrsSize);

    //copy all the sections, one by one:
#ifdef _DEBUG
    std::cout << "Coping sections:" << std::endl;
#endif
    SIZE_T raw_end = 0;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr(payload, payload_size, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
            return false;
        }
        LPVOID section_mapped = (BYTE*)payload + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = destAddress + next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;

        size_t new_end = sec_size + next_sec->PointerToRawData;
        if (new_end > raw_end) raw_end = new_end;

        if (next_sec->VirtualAddress + sec_size > payload_size) {
            //std::cerr << "[!] Virtual section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            printf("[!] Virtual section size is out ouf bounds: %x\n", sec_size);
            sec_size = SIZE_T(payload_size - next_sec->VirtualAddress);
            //std::cerr << "[!] Truncated to maximal size: " << std::hex <<  sec_size << std::endl;
            printf("[!] Truncated to maximal size: %x\n", sec_size);
        }
        if (next_sec->VirtualAddress > payload_size && sec_size != 0) {
            //std::cerr << "[-] VirtualAddress of section is out ouf bounds: " << std::hex << next_sec->VirtualAddress << std::endl;
            printf("[-] VirtualAddress of section is out ouf bounds: %x\n", next_sec->VirtualAddress);
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > payload_size) {
            //std::cerr << "[-] Raw section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            printf("[-] Raw section size is out ouf bounds: %x\n", sec_size);
            return false;
        }
#ifdef _DEBUG
        std::cout << "[+] " << next_sec->Name << " to: " << std::hex << section_raw_ptr << std::endl;
#endif
        memcpy(section_raw_ptr, section_mapped, sec_size);
    }
    if (raw_end > payload_size) raw_end = payload_size;
    if (raw_size_ptr != NULL) {
        (*raw_size_ptr) = raw_end;
    }
    return true;
}
BYTE* load_pe_moduleByte(BYTE* dllRawData, size_t r_size, OUT size_t& v_size, bool executable, bool relocate)
{
    // by default, allow to load the PE at any base:
    ULONGLONG desired_base = NULL;
    // if relocating is required, but the PE has no relocation table...
    if (relocate && !has_relocations(dllRawData)) {
        // ...enforce loading the PE image at its default base (so that it will need no relocations)
        desired_base = get_image_base(dllRawData);
    }
    // load a virtual image of the PE file at the desired_base address (random if desired_base is NULL):
    BYTE* mappedDLL = pe_raw_to_virtual(dllRawData, r_size, v_size, executable, desired_base);
    if (mappedDLL) {
        //if the image was loaded at its default base, relocate_module will return always true (because relocating is already done)
        if (relocate && !relocate_module(mappedDLL, v_size, (ULONGLONG)mappedDLL)) {
            // relocating was required, but it failed - thus, the full PE image is useless
            printf("Could not relocate the module!");
            free_pe_buffer(mappedDLL, v_size);
            mappedDLL = NULL;
        }
    }
    else {
        printf("Could not allocate memory at the desired base!\n");
    }
    return mappedDLL;
}
bool has_relocations(BYTE* pe_buffer)
{
    IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry(pe_buffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (relocDir == NULL) {
        return false;
    }
    return true;
}
BYTE* pe_raw_to_virtual(const BYTE* payload, size_t in_size, size_t& out_size, bool executable, ULONGLONG desired_base)
{
    //check payload:
    BYTE* nt_hdr = get_nt_hrds(payload);
    if (nt_hdr == NULL) {
        //std::cerr << "Invalid payload: " << std::hex << (ULONGLONG) payload << std::endl;
        printf("Invalid payload: %x\n", (ULONGLONG)payload);
        //return false;
        return nullptr;
    }
    ULONGLONG oldImageBase = 0;
    DWORD payloadImageSize = 0;
    ULONGLONG entryPoint = 0;

    bool is64 = is64bit(payload);
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
    DWORD protect = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;

    //first we will prepare the payload image in the local memory, so that it will be easier to edit it, apply relocations etc.
    //when it will be ready, we will copy it into the space reserved in the target process
    BYTE* localCopyAddress = alloc_pe_buffer(payloadImageSize, protect, desired_base);
    if (localCopyAddress == NULL) {
        //std::cerr << "Could not allocate memory in the current process" << std::endl;
        printf("Could not allocate memory in the current process");
        return NULL;
    }
    //printf("Allocated local memory: %p size: %x\n", localCopyAddress, payloadImageSize);
    if (!sections_raw_to_virtual(payload, payloadImageSize, (BYTE*)localCopyAddress)) {
        //std::cerr <<  "Could not copy PE file" << std::endl;
        printf("Could not copy PE file");
        return NULL;
    }
    out_size = payloadImageSize;
    return localCopyAddress;
}
bool sections_raw_to_virtual(const BYTE* payload, SIZE_T destBufferSize, BYTE* destAddress)
{
    if (payload == NULL) return false;

    bool is64b = is64bit(payload);

    BYTE* payload_nt_hdr = get_nt_hrds(payload);
    if (payload_nt_hdr == NULL) {
        //std::cerr << "Invalid payload: " << std::hex << (ULONGLONG) payload << std::endl;
        printf("Invalid payload: %x\n", (ULONGLONG)payload);
        return false;
    }

    IMAGE_FILE_HEADER* fileHdr = NULL;
    DWORD hdrsSize = 0;
    LPVOID secptr = NULL;
    if (is64b) {
        IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr64->FileHeader);
        hdrsSize = payload_nt_hdr64->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr64->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    else {
        IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
        fileHdr = &(payload_nt_hdr32->FileHeader);
        hdrsSize = payload_nt_hdr32->OptionalHeader.SizeOfHeaders;
        secptr = (LPVOID)((ULONGLONG) & (payload_nt_hdr32->OptionalHeader) + fileHdr->SizeOfOptionalHeader);
    }
    if (!validate_ptr((const LPVOID)payload, destBufferSize, (const LPVOID)payload, hdrsSize)) {
        return false;
    }
    //copy payload's headers:
    memcpy(destAddress, payload, hdrsSize);

    //copy all the sections, one by one:
    SIZE_T raw_end = 0;
    for (WORD i = 0; i < fileHdr->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER next_sec = (PIMAGE_SECTION_HEADER)((ULONGLONG)secptr + (IMAGE_SIZEOF_SECTION_HEADER * i));
        if (!validate_ptr((const LPVOID)payload, destBufferSize, next_sec, IMAGE_SIZEOF_SECTION_HEADER)) {
            return false;
        }
        LPVOID section_mapped = destAddress + next_sec->VirtualAddress;
        LPVOID section_raw_ptr = (BYTE*)payload + next_sec->PointerToRawData;
        SIZE_T sec_size = next_sec->SizeOfRawData;
        raw_end = next_sec->SizeOfRawData + next_sec->PointerToRawData;

        if (next_sec->VirtualAddress + sec_size > destBufferSize) {
            //std::cerr << "[!] Virtual section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            printf("[!] Virtual section size is out ouf bounds: \n");
            sec_size = SIZE_T(destBufferSize - next_sec->VirtualAddress);
            //std::cerr << "[!] Truncated to maximal size: " << std::hex << sec_size << std::endl;
            printf("[!] Truncated to maximal size: %x \n", sec_size);
        }
        if (next_sec->VirtualAddress >= destBufferSize && sec_size != 0) {
            //std::cerr << "[-] VirtualAddress of section is out ouf bounds: " << std::hex << next_sec->VirtualAddress << std::endl;
            printf("[-] VirtualAddress of section is out ouf bounds: %x \n", next_sec->VirtualAddress);
            return false;
        }
        if (next_sec->PointerToRawData + sec_size > destBufferSize) {
            //std::cerr << "[-] Raw section size is out ouf bounds: " << std::hex << sec_size << std::endl;
            printf("[-] Raw section size is out ouf bounds: %x \n", sec_size);
            return false;
        }
        memcpy(section_mapped, section_raw_ptr, sec_size);
    }
    return true;
}
bool dump_to_file(const TCHAR* out_path, PBYTE dump_data, size_t dump_size)
{
    HANDLE file = CreateFile(out_path, GENERIC_WRITE, FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        std::cerr << "Cannot open the file for writing!" << std::endl;
#endif
        return false;
    }
    DWORD written_size = 0;
    bool is_dumped = false;
    if (WriteFile(file, dump_data, (DWORD)dump_size, &written_size, nullptr)) {
        is_dumped = true;
    }
#ifdef _DEBUG
    else {
        std::cerr << "Failed to write to the file : " << out_path << std::endl;
    }
#endif
    CloseHandle(file);
    return is_dumped;
}