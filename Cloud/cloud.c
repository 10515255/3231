#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"

#define BUFFER_SIZE 1024 

/*
int storeFile(BIO *client, char *command) {
}
*/

int handleClient(BIO *client) {	
	char buffer[BUFFER_SIZE];
	while(1) {
		int status = readString(client, buffer, sizeof(buffer));
		if(status < 1) {
			printf("readString() faile in handleClient()\n");
			return -1;
		}
		printf("Client: %s", buffer);

		status = writeString(client, "hello");
		if(status < 1) {
			printf("sendString() failed in handleCLient\n");
			return -1;
		}
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
