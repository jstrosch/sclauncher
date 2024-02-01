#include <math.h>

void usage(void) {
	puts("[~] Simple shellcode launcher and debugger! This program can read shellcode from a file or use an internal array.");
	puts("[~] Usage: sclauncher.exe [-f=shellcode.bin] [-o=INT] [-bp]");
	puts("\t-f: path to file to load shellocode. If you don't provide a file, \n\t\t it will check for an internal array - see source code.");
	puts("\t-bp: insert a breakpoint before the shellcode, only use if debugging");
	puts("\t-ep: adjust entry point offset in bytes based on zero-index. Value can be base 10 or hex (prefx with 0x)");
	puts("\t-pe: creates an executable version of the shellcode in a PE file");
	puts("\t-64: PE file creation only, creates a 64-bit PE file - assumes 64-bit shellcode");
}

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

double calculate_entropy(unsigned char* shellcode, int shellcode_size) {
    // using shorts in case an individual byte values in encountered more than a byte can hold
    short prob[256] = {0};
    int i = 0;
    double entropy = 0;
    double p = 0;

    for(i=0; i < shellcode_size; i++) {
        prob[shellcode[i]]++;
    }

    for(i=0; i<256; i++){
        if (prob[i] != 0){
            p = (double)prob[i] / (double)shellcode_size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}