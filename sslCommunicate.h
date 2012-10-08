/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

/* Write until we have sent all <length> bytes. */
int sendAll(BIO *conn, char *buffer, int length);

/* Read until we have received <length> bytes. */
int readAll(BIO *conn, char *buffer, int length);

/* Send a simple packet */
int writePacket(BIO *conn, char *buffer, int length);

/* Receive a simple packet. */
int readPacket(BIO *conn, char *buffer, int maxLength);
