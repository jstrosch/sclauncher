#include <math.h>

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