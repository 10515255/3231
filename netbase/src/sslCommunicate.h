/* Headers and includes for the function in sslCommunicate.h */

#include <openssl/bio.h>

/* Write until we have sent all <length> bytes. */
int sendAll(BIO *conn, char *buffer, int length);

/* Read until we have received <length> bytes. */
int readAll(BIO *conn, char *buffer, int length);

/* Send a simple packet */
int writePacket(BIO *conn, char *buffer, int length);

/* Receive a simple packet. */
int readPacket(BIO *conn, char *buffer, int maxLength);

/* Combine a hostname and port to a "hostname:port" string.
 * Returns a pointer to the new string in dynamic memory. */
char *buildHostString(char *hostname, char *port);

