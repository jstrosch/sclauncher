#include <malloc.h>
#include <stdbool.h>
#include <windows.h>

struct _IMAGE_DOS_STUB 
{
    char data[64];
    //char rich_header[104]; 
};

DWORD align_size(DWORD size, DWORD alignment, DWORD addr){
    if (!(size % alignment))
        return addr + size;
    return addr + (size / alignment + 1) * alignment;
}


void create_pe(char * sc_inject, int shellcode_size, int entry_point, bool is_64, char*output_name, char * additional_content, int additional_content_size) {
    unsigned int tmp_offset = 0, section_padding = 0;
    char* padding_buffer = NULL;
    int num_sections = 1;
    FILE*fp = NULL, *pe = NULL;

    unsigned int file_alignment = 0x200;
    unsigned int section_alignment = 0x1000;

    IMAGE_DOS_HEADER idh = {
        0x5A4D,
        0x0090,
        0x0003,
        0x0000,
        0x0004,
        0x0000,
        0xFFFF,
        0x0000,
        0x00B8,
        0x0000,
        0x0000,
        0x0000,
        0x0040,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x0000,
        0x00000080,
    };

    struct _IMAGE_DOS_STUB ids = {0};
    memmove(&ids.data, "Brought to you by SCLauncher", 28);

    if(additional_content_size)
        num_sections = 2;

    IMAGE_FILE_HEADER ifh = {
        0x14C,
        num_sections,
        0,
        0,
        0,
        224,
        0x0102
    };

    IMAGE_DATA_DIRECTORY idd = {0x00000000, 0x00000000};

    IMAGE_OPTIONAL_HEADER32 ioh = {
        0x10B,
        14,
        16,
        0,
        0,
        0,
        0x1000,
        0x1000,
        0,
        0x400000,
        section_alignment,
        file_alignment,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0,
        0x400,
        0,
        3,
        0x8100,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd
    };

    IMAGE_OPTIONAL_HEADER64 ioh64 = {
        0x20B,//PE32+
        14,
        16,
        0,
        0,
        0,
        0x1000,
        0x1000,
        0x400000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0,
        0x400,
        0,
        3,
        0x8100,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,
        idd,   
    };

    IMAGE_NT_HEADERS32 inh = {
        0x00004550,
        ifh,
        ioh
    };

    IMAGE_NT_HEADERS64 inh64 = {
        0x00004550,
        ifh,
        ioh64
    };

    IMAGE_SECTION_HEADER ish = {
        ".text",
        0,
        0x1000,
        0,
        0x400,
        0,
        0,
        0,
        0,
        0xE0000020
    };

    IMAGE_SECTION_HEADER ish_additional = {
        ".content",
        0,
        0,
        0,
        0x400,
        0,
        0,
        0,
        0,
        0xE0000020    
    };

    //update lfanew based on size of image_dos_header and image_dos_stub
    idh.e_lfanew = (sizeof(idh) + sizeof(ids));

    //calculate difference between headers and first section
    if (is_64) {
        section_padding = 0x400 - (sizeof(idh) + sizeof(ids) + sizeof(inh64) + sizeof(ish));
    } else {
        section_padding = 0x400 - (sizeof(idh) + sizeof(ids) + sizeof(inh) + sizeof(ish));
    }

    if(additional_content_size) {
        section_padding -= sizeof(ish_additional);
    }

    //update entry point
    if( entry_point ) {
        if(is_64) {
            inh64.OptionalHeader.AddressOfEntryPoint = entry_point + 0x1000;
        } else {
            inh.OptionalHeader.AddressOfEntryPoint = entry_point + 0x1000;
        }
    }

    //update the raw and virtual size of the section
    ish.SizeOfRawData = shellcode_size;
    ish.Misc.VirtualSize = shellcode_size;

    if(additional_content_size) {
        ish_additional.PointerToRawData = 0x400 + align_size(shellcode_size, file_alignment, 0);
        ish_additional.SizeOfRawData = align_size(additional_content_size, file_alignment, 0);
        ish_additional.Misc.VirtualSize = align_size(additional_content_size, file_alignment, 0);
        ish_additional.VirtualAddress = align_size(shellcode_size, section_alignment, 0x1000);
    }

    if (is_64) {
        inh64.FileHeader.Machine = 0x8664;
        inh64.OptionalHeader.SizeOfCode = shellcode_size;
        if(additional_content_size) {
            inh64.OptionalHeader.SizeOfImage = ish_additional.Misc.VirtualSize + ish_additional.VirtualAddress;
        } else {
            inh64.OptionalHeader.SizeOfImage =  align_size(shellcode_size, section_alignment, 0x1000);
        }
        inh64.FileHeader.SizeOfOptionalHeader = sizeof(inh64.OptionalHeader);

        inh64.FileHeader.TimeDateStamp = time(NULL);
    } else {
        inh.OptionalHeader.SizeOfCode = shellcode_size;
        //virtual address + section size rounded up. shellcode size will equal section size
        if(additional_content_size) {
            inh.OptionalHeader.SizeOfImage = ish_additional.Misc.VirtualSize + ish_additional.VirtualAddress;
        } else {
            inh.OptionalHeader.SizeOfImage =  align_size(shellcode_size, section_alignment, 0x1000);
        }
        inh.FileHeader.SizeOfOptionalHeader = sizeof(inh.OptionalHeader);

        inh.FileHeader.TimeDateStamp = time(NULL);
    }

    //create array for padding bytes
    padding_buffer = (char*)calloc(section_padding,1);
    puts("");
    if(strlen(output_name) > 0) {
        pe = fopen(output_name, "wb");
        printf("[PE] Done building PE file...created file %s\n", output_name);
    } else if (is_64) {
        pe = fopen("sc_output_x64.exe", "wb");
        printf("[PE] Done building PE file...created file sc_output_x64.exe\n");
    } else {
        pe = fopen("sc_output.exe", "wb");
        printf("[PE] Done building PE file...created file sc_output.exe\n");
    }
    fwrite(&idh,sizeof(idh),1,pe);
    fwrite(&ids,sizeof(ids),1,pe);
    if(is_64) {
        fwrite(&inh64,sizeof(inh64),1,pe);
    } else {
        fwrite(&inh,sizeof(inh),1,pe);
    }
    fwrite(&ish,sizeof(ish),1,pe);
    if(additional_content_size) {
        fwrite(&ish_additional, sizeof(ish_additional), 1, pe);
    }
    fwrite(padding_buffer, _msize(padding_buffer),1,pe);
    fwrite(sc_inject,shellcode_size, 1, pe);

    free(padding_buffer);

    if(additional_content_size) {
        section_padding = align_size(shellcode_size, file_alignment, 0) - shellcode_size;
        if (section_padding){
            padding_buffer = (char*)calloc(section_padding,1);
            fwrite(padding_buffer, _msize(padding_buffer),1,pe);
            free(padding_buffer);
        }
        fwrite(additional_content, additional_content_size, 1, pe);
    }

    fclose(pe);
}