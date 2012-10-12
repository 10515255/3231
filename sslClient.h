
/* Connect to a server at the given hostname on the given port.
 * Once a connection is established it passes the connection to
 * the argument serverHandler() function, which undertakes the
 * actual interaction with the server. */
int connectToServer(char *hostname, char *port, int (*serverHandler)(BIO *) );
