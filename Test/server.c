#include <stdio.h>
#include <stdlib.h>

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

	//init openssl
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	//start the server listening
	runServer(hostname, port, &listenToClient);

	exit(EXIT_SUCCESS);

}
