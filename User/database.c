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

char *convertToHex(unsigned char *bytes, int length) {
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

int main() {
	unsigned char *c = "penguin";
	char *hex = convertToHex(c, 7);
	for(int i=0; i<14; ++i) {
		putchar(hex[i]);
	}
}

