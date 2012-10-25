#include <stdio.h>
#include <stdlib.h>

#include "../netbase/netbase.h"

#define BUFFER_SIZE 1024 

int storeFile(BIO *client, char *command) {
}

int handleClient(BIO *client) {	
	//authenticate the user somehow
	int userid = 1;

	char buffer[BUFFER_SIZE];
	while(1) {
		int status = readString(client, buffer, sizeof(buffer));
		if(strncmp("filesize ", buffer, 9) == 0) {
			status = storeFile(client, buffer);
		}
	}
}

int main(int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];

	initOpenSSL();
	int status = runServer(hostname, port, &handleClient);
	return status;

}
