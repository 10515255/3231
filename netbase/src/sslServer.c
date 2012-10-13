#include <stdio.h>
#include <stdlib.h>

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "sslGeneral.h"
#include "sslServer.h"

/* Start a server, listening for incoming connections.
 * Does not yet use any encryption / SSL / whatever. */
int runServer(char *hostname, char *port, int (*clientHandler)(BIO *)) {

	//setup the BIO structure for this connection
	char *hostString = buildHostString(hostname, port); 
	BIO *acceptor = BIO_new_accept(hostString);
	BIO_set_bind_mode(acceptor, BIO_BIND_REUSEADDR);
	
	//bind and start listening
	if(BIO_do_accept(acceptor) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	while(1) {
		printf("\nListening on %s\n", hostString);

		//accept client connections as they arrive
		if(BIO_do_accept(acceptor) <= 0) {
			fprintf(stderr, "Failed to catch incoming connection?\n");
			continue;
		}
		printf("A client connected!\n");

		//grab the BIO, handle the client connection, then free it
		BIO *client = BIO_pop(acceptor);
		clientHandler(client);
		BIO_free(client);
	}

	//we have finished running the server, free any resources we allocated
	BIO_free_all(acceptor);
	free(hostString);

	return 0;
}
