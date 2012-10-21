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
	//grab any arguments char *hostname = NULL;
	if(argc < 2 || argc > 3) {
		printf("Usage:\n");
		printf(">server hostname port\n");
		printf(">server port\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = (argc == 3) ? argv[1] : NULL;
	char *port = (argc == 3) ? argv[2] : argv[1];

	//start the server listening
	initOpenSSL();
	runServer(port, &listenToClient);

	exit(EXIT_SUCCESS);

}
