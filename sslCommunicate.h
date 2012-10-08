
/* Write until we have sent all <length> bytes. */
int sendAll(BIO *conn, char *buffer, int length);

/* Read until we have received <length> bytes. */
int readAll(BIO *conn, char *buffer, int length);
