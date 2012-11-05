int respondToCommand(BIO *conn, int code, int clientid, EVP_PKEY *clientKey);
int clientListFiles(BIO *conn);
int clientUploadFile(BIO *conn, char *filename);
int clientDownloadFile(BIO *conn, char *filename, int decrypt);
int clientDeleteFile(BIO *conn, char *filename);
int clientVerifyFile(BIO *conn, char *filename);
int clientRefreshHashes(BIO *conn, char *filename);
int clientAddToWallet(BIO *conn, char *filename, EVP_PKEY *privKey);
int clientWalletBalance(BIO *conn);
