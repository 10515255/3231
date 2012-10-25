#include <stdio.h>
#include <stdlib.h>

#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "sslEncrypt.h"
#include "sslGeneral.h"

#define MAX_FILE_SIZE (1024*1024)

/* Load the full contents of a file, into a buffer in memory.
 * Returns the buffer, and fills the size into the argument int.*/
unsigned char *loadFile(char *filename, unsigned int *fileSize) {
	*fileSize = sizeOfFile(filename);

	FILE *ifp = fopen(filename, "rb");
	if(ifp == NULL) {
		perror("loadFile");
		return NULL;
	}

	//allocate space to hold the contents in memory
	unsigned char *buffer = malloc(sizeof(unsigned char) * (*fileSize));
	if(buffer == NULL) {
		fprintf(stderr, "malloc() failed in loadFile\n");
		exit(EXIT_FAILURE);
	}

	//read the contents of the file into the buffer
	int numRead = fread(buffer, 1, (*fileSize), ifp);
	if(numRead != (*fileSize)) {
		perror("loadFile");
		free(buffer);
		return NULL;
	}
	
	return buffer;
}

/* Produce a signature for the given data, using the given private key.
 * Return a char* to the signature in memory, and fill it's length into
 * the argument sigLength. */
unsigned char *signData(void *data, int length, EVP_PKEY *privKey, unsigned int *sigLength) {
	//initialise the digest context
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if(ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	//select SHA512 as the digest to use
	int status = EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	//produce digest for the given data
	status = EVP_SignUpdate(ctx, data, length);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	//allocate space for the signature
	unsigned char *signature = malloc(EVP_PKEY_size(privKey));
	if(signature == NULL) {
		fprintf(stderr, "malloc() failed in signData()\n");
		exit(EXIT_FAILURE);
	}

	//sign the digest
	status = EVP_SignFinal(ctx, signature, sigLength, privKey);
	if(status == 0) {
		free(signature);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	//cleanup digest context and return
	EVP_MD_CTX_destroy(ctx);

	return signature;
}

/* Verify a block of data by computing a digest, and comparing
 * it with the signed digest in the given signature.
 * Return 1 if valid, 0 if invalid and -1 on error. */
int verifyData(void *data, int length, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey) {
	//initialise the digest context
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	if(ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//select SHA512 as the digest to use
	int status = EVP_VerifyInit_ex(ctx, EVP_sha512(), NULL);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_destroy(ctx);
		return -1;
	}

	//produce digest for the given data
	status = EVP_VerifyUpdate(ctx, data, length);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_destroy(ctx);
		return -1;
	}

	//verify the digest against the provided signature
	int match = EVP_VerifyFinal(ctx, signature, sigLength, pubKey);
	if(status == -1) {
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_destroy(ctx);
		return -1;
	}

	//cleanup digest context and return
	EVP_MD_CTX_destroy(ctx);
	return match;
}

/* Encrypte the given block of data using the given key and initialisation vector.
 * Return the results as a block in memory, storing the lengh in outLength */
unsigned char *encryptData(unsigned char *input, int inLength, int *outLength,  unsigned char *key, unsigned char *iv) {
	EVP_CIPHER_CTX context;	
	EVP_CIPHER_CTX_init(&context);
	EVP_CIPHER_CTX *ctx = &context;

	int status = EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	//allocate memory for the encrypted output
	unsigned int maxOutputLength = inLength + EVP_CIPHER_CTX_block_size(ctx);
	printf("Max Output Length = %d\n", maxOutputLength);
	unsigned char *output = malloc(maxOutputLength);
	if(output == NULL) {
		fprintf(stderr, "malloc() failed in encryptData()\n");
		exit(EXIT_FAILURE);
	}

	//encrypt the data
	status = EVP_EncryptUpdate(ctx, output, outLength, input, inLength);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		free(output);
		return NULL;
	}

	//finalise encryption
	int lastBit = 0;
	status = EVP_EncryptFinal_ex(ctx, output + *outLength, &lastBit);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		free(output);
		return NULL;
	}

	*outLength += lastBit;

	//cleanup and return
	EVP_CIPHER_CTX_cleanup(ctx);
	return output;
}

unsigned char *decryptData(unsigned char *input, int inLength, int *outLength, unsigned char *key, unsigned char *iv) {
	EVP_CIPHER_CTX context;	
	EVP_CIPHER_CTX_init(&context);
	EVP_CIPHER_CTX *ctx = &context;

	int status = EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	unsigned int maxOutputLength = inLength + EVP_CIPHER_CTX_block_size(ctx);
	unsigned char *output = malloc(maxOutputLength);
	if(output == NULL) {
		fprintf(stderr, "malloc() failed in decryptData()\n");
		exit(EXIT_FAILURE);
	}

	//decrypt the data
	status = EVP_DecryptUpdate(ctx, output, outLength, input, inLength);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		free(output);
		return NULL;
	}
	
	int lastBit = 0;
	status = EVP_DecryptFinal_ex(ctx, output + *outLength, &lastBit);
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		free(output);
		return NULL;
	}

	*outLength += lastBit;

	//cleanup and return
	EVP_CIPHER_CTX_cleanup(ctx);
	return output;
}

int calculateMD5(unsigned char *bytes, int length,  unsigned char *hash) {

	unsigned char *result = MD5(bytes, length, hash);
	if(result == NULL) {
		fprintf(stderr, "MD5 failed or something.\n");
		return -1;
	}

	return 0;
}


/* Load an RSA structure with the contents of the given file,
 * using the giving function to perform loading. */
EVP_PKEY *loadKey(char *keyFilename, EVP_PKEY *(*keyReader)(FILE *, EVP_PKEY **, pem_password_cb *, void *) ) {
	//open the file and ensure success
	FILE *keyFile = fopen(keyFilename, "r");
	if(keyFile == NULL) {
		perror("loadKey");
		return NULL;
	}

	//allocate the RSA structure, then load it from file 
	EVP_PKEY *key = EVP_PKEY_new();
	if(key != NULL) {
		key = keyReader(keyFile, &key, NULL, NULL);
	}

	//catch failures of EVP_PKEY_new() or keyReader()
	if(key == NULL) {
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(key);
	}

	fclose(keyFile);
	return key;
}

/* Load a private key from the given file into an RSA structure */
EVP_PKEY *loadPrivateKey(char *filename) {
	return loadKey(filename, &PEM_read_PrivateKey);
}

/* Load a public key from the given file into an RSA structure */
EVP_PKEY *loadPublicKey(char *filename) {
	return loadKey(filename, &PEM_read_PUBKEY);
}

unsigned char *randomBytes(int n) {
	unsigned char *output = malloc(n);
	if(output == NULL) {
		fprintf(stderr, "malloc() failed in randomBytes()\n");
		exit(EXIT_FAILURE);
	}

	RAND_bytes(output, n);

	return output;
}

/*
int main(int argc, char **argv) {
	int fileSize;
	unsigned char *file = loadFile(argv[1], &fileSize);

	unsigned char key[32];
	unsigned char iv[32];
	RAND_bytes(key, 32);
	RAND_bytes(iv, 32);



	int outLength;
	unsigned char *output = encryptData(file, fileSize, &outLength, key, iv);
	if(output == NULL) {
		printf("FAIL\n");
	}

	int decryptedSize = 0;
	unsigned char *decrypted = decryptData(output, outLength, &decryptedSize, key, iv);
	for(int i=0; i<decryptedSize; ++i) {
		putchar(decrypted[i]);
	}
	free(file);
	free(output);
	free(decrypted);
	return 0;
}
*/
