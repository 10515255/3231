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
unsigned char *loadFile(char *filename, int *fileSize) {
	//return size of the file we are loading 
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

int writeDataToFile(char *filename, unsigned char *data, int length) {
	FILE *ofp = fopen(filename, "w");
	if(ofp == NULL) {
		perror("writeDataToFile");
		return -1;
	}
	
	int numWritten = fwrite(data, 1, length, ofp);
	if(numWritten < length) {
		perror("fwrite() in writeDataToFile()\n");
		fclose(ofp);
		return -1;
	}

	fclose(ofp);

	return 0;
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

unsigned char *signFile(char *filename, EVP_PKEY *privKey, unsigned int *sigLength) {
	int numBytes;
	unsigned char *bytes = loadFile(filename, &numBytes);
	if(bytes == NULL) return NULL;

	unsigned char *signature = signData(bytes, numBytes, privKey, sigLength);
	free(bytes);
	if(signature == NULL) return NULL;

	return signature;
}

//int verifyData(void *data, int length, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey) {
int verifyFile(char *filename, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey) {
	int numBytes;
	unsigned char *bytes = loadFile(filename, &numBytes);
	if(bytes == NULL) return -1;

	int verified = verifyData(bytes, (unsigned int)numBytes, signature, sigLength, pubKey);
	return verified;

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

int encryptFile(char *filename, char *outFile, unsigned char *key, unsigned char *iv) {
	int numBytes;
	unsigned char *bytes = loadFile(filename, &numBytes);
	if(bytes == NULL) return -1;

	int cipherLength = 0;
	unsigned char *ciphertext = encryptData(bytes, numBytes, &cipherLength , key, iv);
	free(bytes);
	if(ciphertext == NULL) return -1;

	if(writeDataToFile(outFile, ciphertext, cipherLength) == -1) return -1;
	free(ciphertext);

	return 0;
}

int decryptFile(char *filename, char *outFile, unsigned char *key, unsigned char *iv) {
	int cipherLength;
	unsigned char *ciphertext = loadFile(filename, &cipherLength);
	if(ciphertext == NULL) return -1;

	int numBytes = 0;
	unsigned char *bytes = decryptData(ciphertext, cipherLength, &numBytes, key, iv);
	free(ciphertext);
	if(bytes == NULL) return -1;

	if(writeDataToFile(outFile, bytes, numBytes) == -1) return -1;
	free(bytes);

	return 0;
}

unsigned char *calculateMD5(char *filename, unsigned char *salt, int saltSize) {
	EVP_MD_CTX *ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

	//if supplied, run the salt through the digester first
	if(salt != NULL) {
		EVP_DigestUpdate(ctx, salt, saltSize);
	}

	//then run the file through
	FILE *ifp = fopen(filename, "rb");
	if(ifp == NULL) {
		perror(filename);
		return NULL;
	}

	//run the file through the digester a chunk at a time
	int fileSize = sizeOfFile(filename);
	char buffer[BUFSIZ];
	while(fileSize > 0) {
		int amount = (fileSize > sizeof(buffer)) ? sizeof(buffer) : fileSize;
		int numRead = fread(buffer, 1, amount, ifp);
		if(numRead != amount) {
			perror("fread() in calculateMD5()");
			fclose(ifp);
			return NULL;
		}
		//run each chunk through the digester
		EVP_DigestUpdate(ctx, buffer, numRead);

		fileSize -= amount;
	}
	fclose(ifp);

	//allocate space for the digest, and store the final digest in it
	unsigned char *hash = malloc(MD5_DIGEST_LENGTH);
	if(hash == NULL) {
		fprintf(stderr, "malloc() failed in calculateMD5()\n");
		exit(EXIT_FAILURE);
	}
	unsigned int digestSize = 0;
	EVP_DigestFinal(ctx, hash, &digestSize);

	EVP_MD_CTX_destroy(ctx);
	return hash;
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
#include <string.h>

int main(int argc, char **argv) {
	
	EVP_PKEY *privKey = loadPrivateKey(argv[1]);
	EVP_PKEY *pubKey = loadPublicKey(argv[2]);

	unsigned char hash[MD5_DIGEST_LENGTH];
	calculateMD5(argv[3], hash, NULL, 0);


	for(int i=0; i<MD5_DIGEST_LENGTH; ++i) {
		printf("%02x", hash[i]);
	}
	putchar('\n');

	return 0;
}
*/
