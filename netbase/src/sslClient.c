#include <stdio.h>

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "sslGeneral.h"
#include "sslClient.h"

/* Connect to a server at the given hostname on the given port.
 * Once a connection is established it passes the connection to
 * the argument serverHandler() function, which undertakes the
 * actual interaction with the server. */
int connectToServer(char *hostname, char *port, int (*serverHandler)(BIO *) ) {

	//prepare the connection structure
	char *hostString = buildHostString(hostname, port);
	BIO *bio = BIO_new_connect(hostString);
	if(bio == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//attempt to create the connection
	if(BIO_do_connect(bio) <= 0) {
		unsigned long err = ERR_get_error();
		fprintf(stderr, "%s\n", ERR_error_string(err, NULL));
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//hand off the connection to the given handler function
	int status = serverHandler(bio);

	//we are done with this connection, free any resources we allocated
	BIO_free_all(bio);
	free(hostString);

	return status;
}
