#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"

#define READ_BUF_SIZE 1024 

int respondToRequest(BIO *client, char *request) {

		char *reply = "Unexpected command.\n";
		if(strcmp("ls\n", request) == 0) {
			reply = "You want to see your files?\n";
		}
		else if(strcmp("cd\n", request) == 0) {
			reply = "You want to change directory?\n";
		}

		int status = writePacket(client, reply, strlen(reply));
		return status;
}

/* A simple handler for a client connection. */
int listenToClient(BIO *client) {

	char buffer[READ_BUF_SIZE];
	while(1) {
		//read into our buffer, leave room for terminal
		int numRead = readPacket(client, buffer, sizeof(buffer));
		if(numRead < 1) {
			if(numRead == 0) printf("The client disconnected.\n");
			else printf("Error %d from readPacket()\n", numRead); 
			return numRead;
		}
		//really got to add a "sendString" which just delegates
		//to sendPacket, but includes the terminal char
		buffer[numRead] = '\0';
		printf("Client: %s", buffer);

		int status = respondToRequest(client, buffer);
		if(status < 1) {
			printf("Error %d from respondToRequest()\n", status);
			return status;
		}
	}

	return 1;
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
	runServer(hostname, port, &listenToClient);

	exit(EXIT_SUCCESS);

}
