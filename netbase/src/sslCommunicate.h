/* Headers and includes for the functions in sslCommunicate.c */

#include <openssl/bio.h>

/* Write until we have sent all <length> bytes. */
int sendAll(BIO *conn, char *buffer, int length);

/* Read until we have received <length> bytes. */
int readAll(BIO *conn, char *buffer, int length);

/* Send a simple packet */
int writePacket(BIO *conn, char *buffer, int length);

/* Receive a simple packet. */
int readPacket(BIO *conn, char *buffer, int maxLength);

/* Send a string via a simple packet. */
int writeString(BIO *conn, char *buffer);

/* Read a string from a simple packet */
int readString(BIO *conn, char *buffer, int maxLength);

/* Receive a file over the network, as sent by sendFile() above. */
int recvFile(BIO *conn);

/* Send a file across the network. The filename argument
 * will be sent to indicate to the other side what it should
 * be saved as. */
int sendFile(BIO *conn, FILE *file, char *filename);