#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/md5.h>

#include "encryption.h"

#define MAX_FILE_SIZE (1024*1024)

int signFile(char *filename, char *encryptedFilename,  RSA *privateKey) {
	FILE *file = fopen(filename, "rb");
	if(file == NULL) {
		perror("signFile");
		return -1;
	}

	char bytes[MAX_FILE_SIZE];
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	int numRead = fread(bytes, 1, fileSize, file);
	if(numRead != fileSize) {
		perror("signFile");
		fclose(file);
		return -2;
	}
	fclose(file);

	//might be a bit biffer?
	char encrypted[MAX_FILE_SIZE];
	int length = RSA_private_encrypt(fileSize, bytes, encrypted, privateKey, RSA_PKCS1_PADDING);
	
	//write it out
	FILE *ofp = fopen(encryptedFilename, "wb");
	if(ofp == NULL) {
		perror("signFile");
		return -3;
	}

	int numWritten = fwrite(encrypted, 1, length, ofp);
	if(numWritten != length) {
		perror("signFile");
		return -4;
	}

	fclose(ofp);
	return 0;
}

int verifyFile(char *filename, char *decryptedFilename, RSA *publicKey) {
	FILE *file = fopen(filename, "rb");
	if(file == NULL) {
		perror("verifyFile");
		return -1;
	}

	char bytes[MAX_FILE_SIZE];
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	int numRead = fread(bytes, 1, fileSize, file);
	if(numRead != fileSize) {
		perror("verifyFile");
		fclose(file);
		return -2;
	}
	fclose(file);

	//might be a bit biffer?
	char decrypted[MAX_FILE_SIZE];
	int length = RSA_public_decrypt(fileSize, bytes, decrypted, publicKey, RSA_PKCS1_PADDING);
	
	//write it out
	FILE *ofp = fopen(decryptedFilename, "wb");
	if(ofp == NULL) {
		perror("verifyFile");
		return -3;
	}

	int numWritten = fwrite(decrypted, 1, length, ofp);
	if(numWritten != length) {
		perror("verifyFile");
		return -4;
	}

	fclose(ofp);
	return 0;
}

int encryptFile(char *filename, char *encryptedFilename, RSA *publicKey) {
	FILE *file = fopen(filename, "rb");
	if(file == NULL) {
		perror("encryptFile");
		return -1;
	}

	char bytes[MAX_FILE_SIZE];
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	int numRead = fread(bytes, 1, fileSize, file);
	if(numRead != fileSize) {
		perror("encryptFile");
		fclose(file);
		return -2;
	}
	fclose(file);

	char encrypted[MAX_FILE_SIZE];
	int length = RSA_public_encrypt(fileSize, bytes, encrypted, publicKey, RSA_PKCS1_PADDING);
	
	//write it out
	FILE *ofp = fopen(encryptedFilename, "wb");
	if(ofp == NULL) {
		perror("encryptFile");
		return -3;
	}

	int numWritten = fwrite(encrypted, 1, length, ofp);
	if(numWritten != length) {
		perror("encryptFile");
		return -4;
	}

	fclose(ofp);
	return 0;
}

int decryptFile(char *filename, char *decryptedFilename, RSA *privateKey) {
	FILE *file = fopen(filename, "rb");
	if(file == NULL) {
		perror("decryptFile");
		return -1;
	}

	char bytes[MAX_FILE_SIZE];
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);

	int numRead = fread(bytes, 1, fileSize, file);
	if(numRead != fileSize) {
		perror("decryptFile");
		fclose(file);
		return -2;
	}
	fclose(file);

	//might be a bit biffer?
	char decrypted[MAX_FILE_SIZE];
	int length = RSA_private_decrypt(fileSize, bytes, decrypted, privateKey, RSA_PKCS1_PADDING);
	
	//write it out
	FILE *ofp = fopen(decryptedFilename, "wb");
	if(ofp == NULL) {
		perror("decryptFile");
		return -3;
	}

	int numWritten = fwrite(decrypted, 1, length, ofp);
	if(numWritten != length) {
		perror("decryptFile");
		return -4;
	}

	fclose(ofp);
	return 0;
}

int calculateMD5(char *filename, unsigned char *hash) {
	FILE *ifp = fopen(filename, "rb");
	if(ifp == NULL) {
		perror("calculateMD5");
		return -1;
	}
	printf("1");
	fflush(stdout);

	unsigned char bytes[MAX_FILE_SIZE];
	fseek(ifp, 0, SEEK_END);
	long fileSize = ftell(ifp);
	rewind(ifp);
	printf("1");
	fflush(stdout);

	int numRead = fread(bytes, 1, fileSize, ifp);
	if(numRead != fileSize) {
		perror("calculateMD5");
		fclose(ifp);
		return -2;
	}
	printf("1");
	fflush(stdout);

	unsigned char *result = MD5(bytes, fileSize, hash);
	if(result == NULL) {
		fprintf(stderr, "MD5 failed or something.\n");
		return -3;
	}
	printf("1");
	fflush(stdout);

	return 0;
}

int main(int argc, char **argv) {
	printf("1");
	fflush(stdout);
	unsigned char hash[MD5_DIGEST_LENGTH];
	calculateMD5("encryption.c", hash);
	for(int i=0; i<MD5_DIGEST_LENGTH; ++i) {
		putchar(hash[i]);
	}
}
