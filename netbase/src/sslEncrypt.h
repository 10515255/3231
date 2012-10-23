/* Header and include for the funtions in sslEncrypt.c */

#include <openssl/pem.h>

int signFile(char *filename, char *encryptedFilename,  RSA *privateKey);

int verifyFile(char *filename, char *decryptedFilename, RSA *publicKey);

int encryptFile(char *filename, char *encryptedFilename, RSA *publicKey);

int decryptFile(char *filename, char *decryptedFilename, RSA *privateKey); 


/* Load a private key from file into an EVP_PKEY structure */
EVP_PKEY *loadPrivateKey(char *filename);

/* Load a public key from file into an EVP_PKEY structure */
EVP_PKEY *loadPublicKey(char *filename);
