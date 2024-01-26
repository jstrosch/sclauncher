#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "pe_file.h"

//use this as a byte array to load shellcode. Example: char shellcode[2] = "\x55\xEB"
char shellcode[] = ""; 

char* validate_argument(char*arg){
	char*p = NULL;
	p = strstr(arg,"=");
	if (p == NULL){
		printf("[!] Equal sign between \"%s\" parameter not found, exiting!",arg);
		exit(1);
	}
	p++;
	return p;
}

void usage(void) {
	puts("[~] Simple shellcode launcher and debugger! This program can read shellcode from a file or use an internal array.");
	puts("[~] Usage: sclauncher.exe [-f=shellcode.bin] [-o=INT] [-bp]");
	puts("\t-f: path to file to load shellocode. If you don't provide a file, \n\t\t it will check for an internal array - see source code.");
	puts("\t-bp: insert a breakpoint before the shellcode, only use if debugging");
	puts("\t-o: adjust entry point offset in bytes based on zero-index");
	puts("\t-pe: creates an executable version of the shellcode in a PE file. Only 32-bit output files are supported at this time");
	puts("\t-64: PE file creation only, creates a 64-bit PE file - assumes 64-bit shellcode");
}

int main(int argc, char **argv) {
	unsigned int shellcode_size = 0;
	unsigned int offset = 0;
	char hexcc[1] = {0x90};
	int insert_bp = 0;
	char file_path[100] = {0};
	FILE*fp = NULL;
	char produce_pe = 0;
	int is_64 = 0;

	void*stage = NULL;
	int i = 0, len = 0, sc_part1 = 0, sc_part2 = 0;
	size_t bytes_read = 0;
	void* target_addy = NULL;
	char* sc_stage = NULL;
	int arg_count = 0;
	char*command_arg = NULL;

	//parse command-line arguments
	for (arg_count = 0; arg_count < argc; arg_count++) {
		if (!strncmp(argv[arg_count],"-h",2)) {
			usage();
			exit(0);
		} else if (!strncmp(argv[arg_count], "-pe",3)){
			produce_pe = 1;
			printf("[*] Producing a PE file...\n");
		} else if (!strncmp(argv[arg_count],"-ep",3)) {
			command_arg = validate_argument(argv[arg_count]);
			offset = atoi(command_arg);
			printf("[*] Adjusting shellcode entry point: +0x%08x\n", offset);
		} else if(!strncmp(argv[arg_count],"-f",2)){
			command_arg = validate_argument(argv[arg_count]);
			strncpy(file_path,command_arg,strlen(command_arg));
		} else if(!strncmp(argv[arg_count],"-bp",3)){
			insert_bp = 1;
			hexcc[0] = 0xCC;
			puts("[*] Inserting breakpoint before shellcode");
		} else if(!strncmp(argv[arg_count],"-64",3)){
			is_64 = 1;
			puts("[*] Producing a 64-bit PE file");
		}
	}

	//determine where to load shellcode from
	if (strlen(file_path) > 0){
		printf("[*] Loading shellcode from path: %s\n", file_path);
		fp = fopen(file_path,"rb");

		if (fp != NULL){
			fseek(fp, 0L, SEEK_END);
			shellcode_size = ftell(fp);
			if (insert_bp && offset >= shellcode_size) {
				printf("[!] Breakpoint entry point beyond size of shellcode, exiting!");
				exit(1);
			}
			printf("[*] Found %d bytes of shellcode\n",shellcode_size);
			fseek(fp, 0L, SEEK_SET);

			if (produce_pe) {
				puts("[PE] Producing PE file from shellcode found in a file, then exiting.");
				sc_stage = (char*)malloc(shellcode_size);
				fread((char*)sc_stage, sizeof(char), shellcode_size, fp);
				create_pe(sc_stage,shellcode_size, offset, is_64);
				free(sc_stage);
			} else {
				stage = VirtualAlloc(0, shellcode_size + 1, 0x1000,0x40 );
				printf("[*] Allocated memory at %p\n", stage);
				if (insert_bp && offset) {
					bytes_read = fread((char*)stage, sizeof(char), offset-1, fp);
					printf("[*] %zu bytes of shellcode read\n", bytes_read);
					memmove((char*)stage+offset-1, &hexcc, 1);
					printf("[*] Breakpoint inserted at %p\n",(char*)stage+offset-1);
					bytes_read = fread((char*)stage+offset, sizeof(char), (shellcode_size - offset +1), fp);
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
			puts("[!] Error opening file... exiting");
			exit(1);
		}

	} else if(strlen(shellcode)) {
		puts("[*] Loading shellcode from internal array");
		shellcode_size = strlen(shellcode);
		printf("[*] Found %d bytes of shellcode\n",shellcode_size);

		if (produce_pe ) {
			puts("[PE] Producing PE file from shellcode found internally, then exiting.");
			create_pe(shellcode, shellcode_size, offset, is_64);
		} else {
			stage = VirtualAlloc(0, shellcode_size + 1, 0x1000,0x40 );
			printf("[*] Allocated memory at %p\n", stage);
		
			if(insert_bp && offset) {
				memmove(stage, &shellcode, offset -1 );
				memmove((char*) stage+offset-1, &hexcc, 1);
				memmove((char*) stage+offset, &shellcode[offset-1],shellcode_size - offset +1);
			} else if (insert_bp) {
				memmove(stage, &hexcc, 1);
				memmove((char*)stage+1, &shellcode, shellcode_size);
			} else {
				memmove((char*)stage, &shellcode, shellcode_size);
			}
		}
	} else {
		puts("[!] No shellcode found, exiting...");
		exit(1);
	}

	if( !produce_pe) {
		if (offset) {
			target_addy = (char*)stage + offset - 1; //adjust for zero-based address
			printf("[*] Adjusting offset, new entry point: 0x%p\n", target_addy);
		} else {
			target_addy = stage;
		}

		printf("[*} Executing shellcode at %p, enjoy :)\n",target_addy);
		int(*sc)() = target_addy;
		sc();
	}
}