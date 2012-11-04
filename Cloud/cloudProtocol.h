int respondToCommand(BIO *conn, int code, int clientid);
int clientListFiles(BIO *conn);
int clientUploadFile(BIO *conn, char *filename);
int clientDownloadFile(BIO *conn, char *filename, int clientid, int decrypt);
int clientDeleteFile(BIO *conn, char *filename, int clientid);
int clientVerifyFile(BIO *conn, char *filename, int clientid);
int clientRefreshHashes(BIO *conn, char *filename, int clientid);
int clientWallet(BIO *conn, char *filename, int clientid, EVP_PKEY *privKey);
