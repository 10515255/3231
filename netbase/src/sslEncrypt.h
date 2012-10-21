
int signFile(char *filename, char *encryptedFilename,  RSA *privateKey);

int verifyFile(char *filename, char *decryptedFilename, RSA *publicKey);

int encryptFile(char *filename, char *encryptedFilename, RSA *publicKey);

int decryptFile(char *filename, char *decryptedFilename, RSA *privateKey); 
