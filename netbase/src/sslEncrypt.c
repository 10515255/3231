#include <stdio.h>
#include <stdlib.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/md5.h>
#include <openssl/pem.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "sslEncrypt.h"

#define MAX_FILE_SIZE (1024*1024)

/* Load the full contents of a file, into a buffer in memory.
 * Returns the buffer, and fills the size into the argument int.*/
unsigned char *loadFile(char *filename, int *fileSize) {
	//determine the file size
	struct stat s;
	int status = stat(filename, &s);
	if(status == -1) {
		perror("loadFile");
		return NULL;
	}

	FILE *ifp = fopen(filename, "rb");
	if(ifp == NULL) {
		perror("loadFile");
		return NULL;
	}

	//allocate space to hold the contents in memory
	unsigned char *buffer = malloc(sizeof(unsigned char) * s.st_size);
	if(buffer == NULL) {
		fprintf(stderr, "malloc() failed in loadFile\n");
		exit(EXIT_FAILURE);
	}

	//read the contents of the file into the buffer
	int numRead = fread(buffer, 1, s.st_size, ifp);
	if(numRead != s.st_size) {
		perror("loadFile");
		free(buffer);
		return NULL;
	}
	
	*fileSize = s.st_size;
	return buffer;
}

int signFile(char *filename, char *encryptedFilename,  RSA *privateKey) {

	int fileSize = 0;
	//load file into memory and fill fileSize for us
	unsigned char *file = loadFile(filename, &fileSize);

	unsigned char encrypted[MAX_FILE_SIZE];
	int length = RSA_private_encrypt(fileSize, file, encrypted, privateKey, RSA_PKCS1_PADDING);

	//free the original file from memory
	free(file);
	
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

	unsigned char bytes[MAX_FILE_SIZE];
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
	unsigned char decrypted[MAX_FILE_SIZE];
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

	unsigned char bytes[MAX_FILE_SIZE];
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

	unsigned char encrypted[MAX_FILE_SIZE];
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

	unsigned char bytes[MAX_FILE_SIZE];
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
	unsigned char decrypted[MAX_FILE_SIZE];
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


/* Load an RSA structure with the contents of the given file,
 * using the giving function to perform loading. */
RSA *loadKey(char *keyFilename, RSA *(*keyReader)(FILE *, RSA **, pem_password_cb *, void *) ) {
	//open the file and ensure success
	FILE *keyFile = fopen(keyFilename, "r");
	if(keyFile == NULL) {
		perror("loadKey");
		return NULL;
	}

	//allocate the RSA structure, load it from file 
	RSA *key = RSA_new();
	if(key != NULL) {
		key = keyReader(keyFile, &key, NULL, NULL);
	}

	//catch failures of RSA_new() or keyReader()
	if(key == NULL) {
		ERR_print_errors_fp(stderr);
		RSA_free(key);
	}

	fclose(keyFile);
	return key;
}

/* Load a private key from the given file into an RSA structure */
RSA *loadPrivateKey(char *filename) {
	return loadKey(filename, &PEM_read_RSAPrivateKey);
}

/* Load a public key from the given file into an RSA structure */
RSA *loadPublicKey(char *filename) {
	return loadKey(filename, &PEM_read_RSA_PUBKEY);
}

/*
int main(int argc, char **argv) {
	int filesize;
	unsigned char *file = loadFile(argv[1], &filesize);
	for(int i=0; i<filesize; ++i) {
		putchar(file[i]);	
	}
	free(file);
	return 0;
}
*/
