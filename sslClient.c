#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "sslCommunicate.h"

/* Just read lines from stdin, the send them in a packet to the server. */
int handleServer(BIO *server) {
	char buffer[1024];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		int status = writePacket(bio, buffer, strlen(buffer));
		if(status < 1) {
			fprintf(stderr, "Error %d from writePacket()\n", status);
			if(status == 0) printf("They closed the connection.\n");
			return status;
		}
	}

	//what to return?
	return 1;
}

/* Connect to a server at the given hostname on the given port.
 * Once a connection is established it passes the connection to
 * the argument serverHandler() function, which undertakes the
 * actual interaction with the server. */
int connectToServer(char *hostname, char *port, int (*serverHandler)(BIO *) ) {

	//combine the hostname and port into a string "hostname:port"
	char *hostString = malloc(strlen(hostname) + strlen(port) + 2);
	if(hostString == NULL) return -1;
	sprintf(hostString, "%s:%s", hostname, port);
	printf("Attempting to connect to %s\n", hostString);
	
	//prepare the connection?
	BIO *bio = BIO_new_connect(hostString);
	if(bio == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//attempt to create the connection?
	if(BIO_do_connect(bio) <= 0) {
		unsigned long err = ERR_get_error();
		fprintf(stderr, "%s\n", ERR_error_string(err, NULL));
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//release resources we allocated
	BIO_free_all(bio);
	free(hostString);

	return 0;
}

/* Check sufficient arguments, prepare OpenSSL and kickstart the connection. */
int main(int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];

	/* OpenSSL initialisation */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	openConnection(hostname, port);
}
