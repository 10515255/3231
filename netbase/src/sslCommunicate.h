/* Headers and includes for the functions in sslCommunicate.c */

#include <openssl/bio.h>

#define NO_SUCH_FILE -2 

/* Write until we have sent all <length> bytes. */
int writeAll(BIO *conn, char *buffer, int length);

/* Read until we have received <length> bytes. */
int readAll(BIO *conn, char *buffer, int length);

/* Read a 4 bytes int from the connection */
int readInt(BIO *conn);

/* Send a 4 byte int over the connection */
int writeInt(BIO *conn, int n);

/* Send a simple packet */
int writePacket(BIO *conn, char *buffer, int length);

/* Receive a simple packet. */
int readPacket(BIO *conn, char *buffer, int maxLength);

/* Send a string via a simple packet. */
int writeString(BIO *conn, char *buffer);

/* Read a string from a simple packet */
int readString(BIO *conn, char *buffer, int maxLength);

/* Write a file over the network. */
int writeFile(BIO *conn, char *filename, char *writeName);

/* Receive a file over the network, as sent by sendFile() above. */
int recvFile(BIO *conn, char *filename);

