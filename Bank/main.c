#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "../netbase/netbase.h"

#define MAX_FILE_SIZE 1024

RSA *privateKey;
RSA *publicKey;

int loadKeys(char *privateFilename, char *publicFilename) {
	FILE *privateFile = fopen(privateFilename, "r");
	if(privateFile == NULL) {
		perror("loadKeys");
		return -1;
	}
	privateKey = RSA_new();
	RSA *result = PEM_read_RSAPrivateKey(privateFile, &privateKey, NULL, NULL);
	if(result == NULL) {
		ERR_print_errors_fp(stderr);
		fclose(privateFile);
		return -1;
	}
	fclose(privateFile);

	FILE *publicFile = fopen(publicFilename, "r");
	if(publicFile == NULL) {
		perror("loadKeys");
		return -1;
	}
	publicKey = RSA_new();
	result = PEM_read_RSA_PUBKEY(publicFile, &publicKey, NULL, NULL);
	if(result == NULL) {
		ERR_print_errors_fp(stderr);
		fclose(publicFile);
		return -1;
	}
	fclose(publicFile);

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
