#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"
#include "cloudProtocol.h"

#define BUFFER_SIZE 1024 

/*
int storeFile(BIO *client, char *command) {
}
*/

int handleClient(BIO *client) {	
	/* Accept commands codes from the client program to determine which 
	 * functionality of the protocol is being initiate. */
	while(1) {
		int commandCode = readInt(client);
		if(commandCode == -1) return -1;
		printf("Client: %d\n", commandCode);

		if(respondToCommand(client, commandCode) == -1) return -1;
	}


	return 0;
}

int main(int argc, char **argv) {
	if(argc < 6) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];
	char *certFile = argv[3];
	char *privKeyFile = argv[4];
	char *trustStore = argv[5];

	initOpenSSL();
	int status = runServer(hostname, port, certFile, privKeyFile, trustStore, &handleClient);
	return status;

}
