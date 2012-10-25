/* Headers and includes for the functions in sslServer.c */

#include <openssl/bio.h>

/* Start a server, listening for incoming connections.
 * Does not yet use any encryption / SSL / whatever. */
int runServer(char *hostname, char *port, char *certFile, char *privKeyFile, char *trustStore, int (*clientHandler)(BIO *));

