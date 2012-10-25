/* Header and include for the funtions in sslEncrypt.c */

#include <openssl/pem.h>

unsigned char *loadFile(char *filename, unsigned int *fileSize);

unsigned char *signData(void *data, int length, EVP_PKEY *privKey, unsigned int *sigLength);

int verifyData(void *data, int length, unsigned char *signature, unsigned int sigLength, EVP_PKEY *pubKey); 

unsigned char *encryptData(unsigned char *input, int inLength, int *outLength,  unsigned char *key, unsigned char *iv);

unsigned char *decryptData(unsigned char *input, int inLength, int *outLength, unsigned char *key, unsigned char *iv);

int calculateMD5(unsigned char *bytes, int length, unsigned char *hash);

/* Load a private key from file into an EVP_PKEY structure */
EVP_PKEY *loadPrivateKey(char *filename);

/* Load a public key from file into an EVP_PKEY structure */
EVP_PKEY *loadPublicKey(char *filename);

unsigned char *randomBytes(int n);
