/* Header and include for the funtions in sslEncrypt.c */

#include <openssl/pem.h>

unsigned char *loadFile(char *filename, int *fileSize);

int writeDataToFile(char *filename, unsigned char *data, int length);

/* Produce a signature for the given block of data using the given
 * private key.  Return a pointer to the signature, and store the length in
 * the int pointed to by sigLength. */
unsigned char *signData(void *data, int length, EVP_PKEY *privKey, unsigned int *sigLength);

/* Verify that the given signature was produced by signing the given block
 * of data, using the corresponding private key of the given public key. */
int verifyData(void *data, int length, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey); 

/* Produce a signature for the given file, using the given private key.
 * Returns a pointer to the signature and stores the length in the int
 * pointed to by sigLength. */
unsigned char *signFile(char *filename, EVP_PKEY *privKey, unsigned int *sigLength);

/* Verify that the given signature was produced by signing the contents of the
 * given file with the corresponding private key to the given public key.*/
int verifyFile(char *filename, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey);

/* Encrypt the given block of data using the provided key and iv.
 * Allocates space and returns a pointer to the encrypted result, storing 
 * the size in the int pointed to by outLength */
unsigned char *encryptData(unsigned char *input, int inLength, int *outLength,  unsigned char *key, unsigned char *iv);

/* Decrypt the encrypted block of data using the provided key and iv.
 * Allocates space and returns a pointer to the decrypted result, storing
 * the size in the int pointed to by outlength. */
unsigned char *decryptData(unsigned char *input, int inLength, int *outLength, unsigned char *key, unsigned char *iv);

/* Encrypt the given file, using the given key and iv, producing a new file
 * with the name outFile. */
int encryptFile(char *filename, char *outFile, unsigned char *key, unsigned char *iv);

/* Decrypt an encrypted file, using the given key and iv, saving the 
 * result as outFile */
int decryptFile(char *filename, char *outFile, unsigned char *key, unsigned char *iv);


/* Calculate the MD5 hash of the given file, and store it in the
 * argument buffer "hash", which should be MD5_DIGEST_LENGTH in size.
 * If salt is not NULL its contents will be pushed in ahead of the file
 * contents. */
unsigned char *calculateMD5(char *filename, unsigned char *salt, int saltSize);

/* Load a private key from file into an EVP_PKEY structure */
EVP_PKEY *loadPrivateKey(char *filename);

/* Load a public key from file into an EVP_PKEY structure */
EVP_PKEY *loadPublicKey(char *filename);

/* Return a pointer to a block of n randomly chosen bytes.
 * Used to generate random keys and ivs. */
unsigned char *randomBytes(int n);
