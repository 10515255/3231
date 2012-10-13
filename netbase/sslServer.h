/* Start a server, listening for incoming connections.
 * Does not yet use any encryption / SSL / whatever. */
int runServer(char *hostname, char *port, int (*clientHandler)(BIO *)) {
