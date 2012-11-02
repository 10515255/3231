/* Header and include for the funtions in sslEncrypt.c */

#include <openssl/pem.h>

unsigned char *loadFile(char *filename, int *fileSize);

int writeDataToFile(char *filename, unsigned char *data, int length);

unsigned char *signData(void *data, int length, EVP_PKEY *privKey, unsigned int *sigLength);

int verifyData(void *data, int length, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey); 

unsigned char *signFile(char *filename, EVP_PKEY *privKey, unsigned int *sigLength);

int verifyFile(char *filename, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey);

unsigned char *encryptData(unsigned char *input, int inLength, int *outLength,  unsigned char *key, unsigned char *iv);

unsigned char *decryptData(unsigned char *input, int inLength, int *outLength, unsigned char *key, unsigned char *iv);

int encryptFile(char *filename, char *outFile, unsigned char *key, unsigned char *iv);

int decryptFile(char *filename, char *outFile, unsigned char *key, unsigned char *iv);


int calculateMD5(char *filename,unsigned char *hash,  unsigned char *salt, int saltSize);

/* Load a private key from file into an EVP_PKEY structure */
EVP_PKEY *loadPrivateKey(char *filename);

/* Load a public key from file into an EVP_PKEY structure */
EVP_PKEY *loadPublicKey(char *filename);

unsigned char *randomBytes(int n);
