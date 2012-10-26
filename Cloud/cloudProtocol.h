int respondToCommand(BIO *conn, int code, int clientid);
int clientListFiles(BIO *conn);
int clientUploadFile(BIO *conn, char *filename);
int clientDownloadFile(BIO *conn, char *filename, int clientid);
int clientDeleteFile(BIO *conn, char *filename, int clientid);
