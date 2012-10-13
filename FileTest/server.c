#include <stdio.h>
#include <stdlib.h>

#include "../netbase/netbase.h"

#define READ_BUF_SIZE 1024 

/* A simple handler for a client connection. */
int listenToClient(BIO *client) {

	int status = recvFile(client);
	printf("Status %d\n", status);
	return status;
}

int main(int argc, char **argv) {
	//grab any arguments
	if(argc < 2) {
		fprintf(stderr, "Expected a port number.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = NULL;
	char *port = argv[1];


	//start the server listening
	initOpenSSL();
	runServer(hostname, port, &listenToClient);

	exit(EXIT_SUCCESS);

}
