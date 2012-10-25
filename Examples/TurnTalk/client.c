#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../netbase/netbase.h"

/* Just read lines from stdin, the send them in a packet to the server. */
int handleServer(BIO *server) {

	char buffer[1024];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		int status = writePacket(server, buffer, strlen(buffer));
		if(status < 1) {
			fprintf(stderr, "Error %d from writePacket()\n", status);
			if(status == 0) printf("They closed the connection.\n");
			return status;
		}

		if(strncmp(buffer, "grab ", 5) == 0) {
			status = recvFile(server);
			continue;
		}
		//now read a packet
		status = readPacket(server, buffer, sizeof(buffer));	
		if(status < 1) {
			fprintf(stderr, "Error %d from writePacket()\n", status);
			return status;
		}

		buffer[status] = '\0';
		printf("Server: %s", buffer);
	}

	//what to return?
	return 1;
}

/* Check sufficient arguments, prepare OpenSSL and kickstart the connection. */
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

	//connect to the server, then run handleServer() on the resulting connection
	initOpenSSL();
	int status = connectToServer(hostname, port, certFile, privKeyFile, trustStore, &handleServer);

	return status;
}
