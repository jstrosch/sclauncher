#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "pe_file.h"
#include "utils.h"

int main(int argc, char **argv) {
	int arg_count = 0;
	char*command_arg = NULL;

	unsigned int shellcode_size = 0;
	unsigned int additional_content_size = 0;

	unsigned int entry_point = 0;
	char hexcc[1] = {0x90};
	
	bool insert_bp = false;
	bool produce_pe = false;
	bool pause = false;
	bool is_64 = false;
	bool mem_map_additional = false;
	
	char*sc_path = NULL;
	char*additional_content_path = NULL;
	char*output_name = NULL;
	
	FILE* shellcode_file = NULL;
	FILE* additional_file = NULL;
	HANDLE hadditional_content = NULL;
	HANDLE hfile_mapping = NULL;

	void* stage = NULL;
	void* additional_content = NULL;
	DWORD bytes_read = 0;
	void* target_addy = NULL;
	char* sc_stage = NULL;
	char* additional_content_stage = NULL;

	banner();

	//parse command-line arguments
	for (arg_count = 0; arg_count < argc; arg_count++) {
		if (!strncmp(argv[arg_count],"-h",2)) {
			usage();
			exit(0);
		} else if (!strncmp(argv[arg_count], "-pe",3)){
			produce_pe = true;
			printf("[*] Producing a PE file...\n");
		} else if (!strncmp(argv[arg_count],"-ep",3)) {
			command_arg = validate_argument(argv[arg_count]);
			if (!strncmp(command_arg, "0x", 2)){
				entry_point = strtol(command_arg, NULL, 16);
			} else {
				entry_point = atoi(command_arg);
			}
			printf("[*] Adjusting shellcode entry point: +0x%08x\n", entry_point);
		} else if(!strncmp(argv[arg_count],"-f",2)){
			command_arg = validate_argument(argv[arg_count]);
			sc_path = command_arg;
		} else if(!strncmp(argv[arg_count],"-bp",3)){
			insert_bp = true;
			hexcc[0] = 0xCC;
			puts("[*] Inserting breakpoint before shellcode");
		} else if(!strncmp(argv[arg_count],"-64",3)){
			is_64 = true;
			puts("[*] Producing a 64-bit PE file");
		} else if(!strncmp(argv[arg_count],"-pause",6)) {
			pause = true;
			puts("[*] Pausing before executing shellcode");
		} else if(!strncmp(argv[arg_count],"-o", 2)) {
			command_arg = validate_argument(argv[arg_count]);
			output_name = command_arg;
		} else if(!strncmp(argv[arg_count], "-d",2)) {
			command_arg = validate_argument(argv[arg_count]);
			additional_content_path = command_arg;
		} else if(!strncmp(argv[arg_count], "-mm", 3)) {
			mem_map_additional = true;
			puts("[*] Memory mapping additional content file");
		}
	}
	puts("");

	if (sc_path){
		printf("[*] Loading shellcode from path: %s\n", sc_path);
		shellcode_file = fopen(sc_path,"rb");

		if (shellcode_file != NULL){
			fseek(shellcode_file, 0L, SEEK_END);
			shellcode_size = ftell(shellcode_file);
			if (insert_bp && entry_point >= shellcode_size) {
				printf("[!] Breakpoint entry point beyond size of shellcode, exiting!");
				exit(1);
			}
			printf("[*] Found %d bytes of shellcode\n",shellcode_size);
			fseek(shellcode_file, 0L, SEEK_SET);

			if (additional_content_path){
				printf("[*] Loading additional content from path: %s\n", additional_content_path);
				
				hadditional_content = CreateFile(additional_content_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
                             FILE_ATTRIBUTE_NORMAL, NULL);

				if (hadditional_content != INVALID_HANDLE_VALUE) {
					additional_content_size = GetFileSize(hadditional_content, NULL);
					printf("\t[*] Found %d bytes of additional content\n", additional_content_size);
				} else {
					printf("\t[!] Error opening additional content file from %s, skipping!", additional_content_path);
				}
			}

			sc_stage = calloc(shellcode_size, sizeof(char));
			fread((char*)sc_stage, sizeof(char), shellcode_size, shellcode_file);
			printf("\t[~] Shellcode has entropy of %.2f\n", calculate_entropy(sc_stage, shellcode_size));
			fseek(shellcode_file, 0L, SEEK_SET);
			free(sc_stage);

			if (produce_pe) {
				puts("[PE] Producing PE file from shellcode, then exiting.");
				sc_stage = (char*)malloc(shellcode_size);
				fread((char*)sc_stage, sizeof(char), shellcode_size, shellcode_file);

				if(additional_content_path) {
					additional_file = fopen( additional_content_path,"rb");
					additional_content_stage = (char*)malloc(additional_content_size);
					fread((char*)additional_content_stage, sizeof(char), additional_content_size, additional_file);
				}
				
				create_pe(sc_stage,shellcode_size, entry_point, is_64, output_name, additional_content_stage, additional_content_size);
				free(sc_stage);
				free(additional_content_stage);
			} else {
				stage = VirtualAlloc(0, shellcode_size + 1, 0x1000,0x40 );
				printf("[*] Allocated memory for shellcode at 0x%p\n", stage);

				if(mem_map_additional) {
					hfile_mapping = CreateFileMapping(hadditional_content, NULL, PAGE_READONLY, 0, 0, NULL);

					additional_content = MapViewOfFile(hfile_mapping, FILE_MAP_READ, 0, 0, additional_content_size);

					printf("[*] Additional content memory mapped to 0x%p\n", additional_content);
				} else {
					additional_content = VirtualAlloc(0, additional_content_size, 0x1000, 0x40);
					
					if ( additional_content ) {
						ReadFile(hadditional_content, additional_content, additional_content_size, &bytes_read, NULL);
						printf("[*] Additional content loaded at 0x%p\n", additional_content);
					}
				}

				if (additional_content_path && !additional_content) {
					puts("[!] Error allocating memory for additional content, skipping...");
				}

				if (insert_bp && entry_point) {
					bytes_read = 0;
					bytes_read = fread((char*)stage, sizeof(char), entry_point, shellcode_file);
					printf("[*] %u bytes of shellcode read\n", bytes_read);
					memmove((char*)stage+entry_point, &hexcc, 1);
					printf("[*] Breakpoint inserted at %p\n",(char*)stage+entry_point );
					bytes_read = fread((char*)stage+entry_point + 1, sizeof(char), (shellcode_size - entry_point), shellcode_file);
					printf("[*] %u remaining bytes of shellcode read\n", bytes_read);
				} else if (insert_bp) {
					memmove(stage, &hexcc, 1);
					fread((char*)stage+1, sizeof(char), shellcode_size, shellcode_file);
				} else {
					fread((char*)stage, sizeof(char), shellcode_size, shellcode_file);
				}
			}
			fclose(shellcode_file);
		} else {
			puts("[!] Error opening file... exiting!");
			exit(1);
		}
	} else {
		puts("[!] shellcode path required... exiting!");
		exit(1);
	}

	puts("");
	if( !produce_pe) {
		if (entry_point) {
			target_addy = (char*)stage + entry_point; //adjust for zero-based address
			printf("[*] Adjusting entry_point, new entry point: 0x%p\n", target_addy);
		} else {
			target_addy = stage;
		}
		if (pause) {
			printf("[!] PID is %lu - Attach debugger, set additional breakpoint(s) and press enter to begin execution", getpid());
			getchar();
		}
		printf("[*} Executing shellcode at %p, enjoy :)\n",target_addy);
		int(*sc)() = target_addy;
		sc();
	}
}