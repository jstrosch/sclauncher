#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "pe_file.h"
#include "utils.h"

int main(int argc, char **argv) {
	unsigned int shellcode_size = 0;
	unsigned int entry_point = 0;
	char hexcc[1] = {0x90};
	bool insert_bp = false;
	bool produce_pe = false;
	bool pause = false;
	bool is_64 = false;
	char sc_path[100] = {0};
	FILE*fp = NULL;
	
	void*stage = NULL;
	int i = 0, len = 0;
	size_t bytes_read = 0;
	void* target_addy = NULL;
	char* sc_stage = NULL;
	int arg_count = 0;
	char*command_arg = NULL;

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
			strncpy(sc_path,command_arg,strlen(command_arg));
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
		}
	}
	puts("");

	if (strlen(sc_path) > 0){
		printf("[*] Loading shellcode from path: %s\n", sc_path);
		fp = fopen(sc_path,"rb");

		if (fp != NULL){
			fseek(fp, 0L, SEEK_END);
			shellcode_size = ftell(fp);
			if (insert_bp && entry_point >= shellcode_size) {
				printf("[!] Breakpoint entry point beyond size of shellcode, exiting!");
				exit(1);
			}
			printf("[*] Found %d bytes of shellcode\n",shellcode_size);
			fseek(fp, 0L, SEEK_SET);

			sc_stage = calloc(shellcode_size, sizeof(char));
			fread((char*)sc_stage, sizeof(char), shellcode_size, fp);
			printf("[~] Shellcode has entropy of %.2f\n", calculate_entropy(sc_stage, shellcode_size));
			fseek(fp, 0L, SEEK_SET);
			free(sc_stage);

			if (produce_pe) {
				puts("[PE] Producing PE file from shellcode found in a file, then exiting.");
				sc_stage = (char*)malloc(shellcode_size);
				fread((char*)sc_stage, sizeof(char), shellcode_size, fp);
				create_pe(sc_stage,shellcode_size, entry_point, is_64);
				free(sc_stage);
			} else {
				stage = VirtualAlloc(0, shellcode_size + 1, 0x1000,0x40 );
				printf("[*] Allocated memory at %p\n", stage);
				if (insert_bp && entry_point) {
					bytes_read = fread((char*)stage, sizeof(char), entry_point, fp);
					printf("[*] %zu bytes of shellcode read\n", bytes_read);
					memmove((char*)stage+entry_point, &hexcc, 1);
					printf("[*] Breakpoint inserted at %p\n",(char*)stage+entry_point );
					bytes_read = fread((char*)stage+entry_point + 1, sizeof(char), (shellcode_size - entry_point), fp);
					printf("[*] %zu remaining bytes of shellcode read\n", bytes_read);
				} else if (insert_bp) {
					memmove(stage, &hexcc, 1);
					fread((char*)stage+1, sizeof(char), shellcode_size, fp);
				} else {
					fread((char*)stage, sizeof(char), shellcode_size, fp);
				}
			}
			fclose(fp);
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
			printf("[!] PID is %lu - Attach debugger, set additional breakpoint(s) and press any key", getpid());
			getchar();
		}
		printf("[*} Executing shellcode at %p, enjoy :)\n",target_addy);
		int(*sc)() = target_addy;
		sc();
	}
}