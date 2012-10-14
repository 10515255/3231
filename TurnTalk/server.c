#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"

#define READ_BUF_SIZE 1024 

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

		if(fgets(buffer, sizeof(buffer), stdin) == NULL) {
			printf("Server failed ot talk!\n");
			continue;
		}
		int status = writePacket(client, buffer, strlen(buffer));
		if(status < 1) {
			printf("Error %d from writePacket()\n", status);
			return status;
		}
	}

	return 1;
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
