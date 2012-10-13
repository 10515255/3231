#include <stdio.h>
#include <stdlib.h>

#define READ_BUF_SIZE 1024 

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "sslCommunicate.h"

/* A simple handler for a client connection. */
int listenToClient(BIO *client) {

	char buffer[READ_BUF_SIZE];
	while(1) {
		//read into our buffer, leave room for terminal
		int numRead = readPacket(client, buffer, sizeof(buffer));
		if(numRead < 1) {
			if(numRead == 0) printf("The client disconnected.\n");
			else printf("Error %d from readPacket()\n", numRead); 
			break;
		}

		buffer[numRead] = '\0';
		printf("Client: %s", buffer);
	}

	return 1;
}

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


int main(int argc, char **argv) {
	//grab any arguments
	if(argc < 2) {
		fprintf(stderr, "Expected a port number.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = NULL;
	char *port = argv[1];

	//init openssl
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	//start the server listening
	runServer(hostname, port, &listenToClient);

	exit(EXIT_SUCCESS);

}
