/* Initialise OpenSSL for use */
void initOpenSSL();

/* Combine a hostname and port to a "hostname:port" string.
 * Returns a pointer to the new string in dynamic memory. */
char *buildHostString(char *hostname, char *port);
