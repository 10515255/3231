#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"

/* Just read lines from stdin, the send them in a packet to the server. */
int handleServer(BIO *server) {

	FILE *ifp = fopen("test.txt", "rb");
	if(ifp == NULL) {
		perror("fopen() in handleServer():");
		return -1;
	}
	int status = sendFile(server, ifp, "bug.txt");
	return status;
}

/* Check sufficient arguments, prepare OpenSSL and kickstart the connection. */
int main(int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];

	//connect to the server, then run handleServer() on the resulting connection
	initOpenSSL();
	int status = connectToServer(hostname, port, &handleServer);

	return status;
}
