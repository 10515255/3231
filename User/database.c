#include <stdio.h>
#include <stdlib.h>

unsigned char nibbleToHex(unsigned char nibble) {
	if(0 <= nibble && nibble < 10) return '0' + nibble;
	if(10 <= nibble && nibble < 16) return 'A' + nibble - 10;
	else {
		fprintf(stderr, "Unexpected value passed to nibbleToHex()\n");
		return 'G';
	}
}

unsigned char hexToNibble(unsigned char hex) {
	if('0' <= hex && hex <= '9') return hex - '0';
	if('A' <= hex && hex <= 'F') return hex - 'A' + 10;
	else {
		fprintf(stderr, "Unexpected value passed to hexToNibble()\n");
		return '0';
	}
}
unsigned char *bytesToHex(unsigned char *bytes, int length) {
	unsigned char *hex = malloc(length*2);
	if(hex == NULL) {
		fprintf(stderr, "malloc() failed in convertToHex()\n");
		exit(EXIT_FAILURE);
	}

	for(int i=0; i < length; ++i) {
		unsigned char c = bytes[i];	
		unsigned char lower = c & 0x0f;
		unsigned char upper = (c >> 4) & 0x0f;
		hex[2*i] = nibbleToHex(upper);
		hex[2*i+1] = nibbleToHex(lower);
	}

	return hex;
}

unsigned char *hexToBytes(unsigned char *hex, int length) {
	if(length % 2 != 0) {
		fprintf(stderr, "bytesFromHex() passed odd number of hex chars.\n");
		return NULL;
	}
	int numBytes = length / 2;
	unsigned char *bytes = malloc(numBytes);
	if(bytes == NULL) {
		fprintf(stderr, "malloc() failed in bytesFromHex()\n");
		exit(EXIT_FAILURE);
	}

	for(int i=0; i < numBytes; ++i) {
		//byte = lower + upper << 4
		unsigned char upper = hexToNibble(hex[2*i]);
		unsigned char lower = hexToNibble(hex[2*i+1]);
		bytes[i] = lower | (upper << 4); 
	}

	return bytes;
}

int main() {
	unsigned char *c = "0F00FFA9";
	char *hex = hexToBytes(c, 8);
	for(int i=0; i<4; ++i) {
		putchar(hex[i]);
	}
	putchar('\n');

	char *bytes = bytesToHex(hex, 4);
	for(int i=0; i<8; ++i) {
		putchar(bytes[i]);
	}

	free(bytes);
	free(hex);
}

