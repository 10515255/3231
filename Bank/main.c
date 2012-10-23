#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "../netbase/netbase.h"

#define MAX_FILE_SIZE 1024

EVP_PKEY *privateKey;
EVP_PKEY *publicKey;

int loadKeys(char *privateFilename, char *publicFilename) {
	privateKey = loadPrivateKey(privateFileName);	
	publicKey = loadPublicKey(publicFilename);

	if(privateKey == NULL || publicKey == NULL) return -1;
	return 0;
}

int buildCloudDollar(int serial, int amount) {
	FILE *temp = fopen("temp.j", "wb");
	if(temp == NULL) {
		perror("buildCloudDollar");
		return -1;
	}
	
	char *message = "This is a certified cloud cheque issued by CLOUD BANK.\n";
	fprintf(temp, message); 
	fprintf(temp, "Serial: %010d\n", serial);
	fprintf(temp, "Amount: %010d\n", amount);
	fclose(temp);

	char noteName[1024];
	sprintf(noteName, "CHEQUE%010d.cd");
	int status = signFile("temp.j", noteName, privateKey); 
	if(status < 0) {
		return -2;
	}

	status = unlink("temp.j");
	if(status < 0) {
		perror("buildCloudDollar");
		return -3;
	}
	
	return 0;
}

int main(int argc, char **argv) {
	if(argc < 3) {
		printf("Insufficient arguments.\n");
		exit(EXIT_FAILURE);	
	}

	loadKeys(argv[1], argv[2]);
	buildCloudDollar(1, 10);
}
