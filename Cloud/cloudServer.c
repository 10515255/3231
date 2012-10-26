#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"
#include "cloudProtocol.h"

#define BUFFER_SIZE 1024 

#define TRUST_STORE "Certs/1Cert.pem"
#define SERVER_CERTIFICATE "Certs/cloudCert.pem"
#define SERVER_PRIVKEY "Certs/cloudPrivateKey.pem"


int handleClient(BIO *client) {	
	//find out who the user is
	int userid = readInt(client);
	if(userid == -1) return -1;
	printf("User %d has connected.\n", userid);

	/* Accept commands codes from the client program to determine which 
	 * functionality of the protocol is being initiate. */
	while(1) {
		int commandCode = readInt(client);
		if(commandCode == -1) return -1;
		printf("Client: %d\n", commandCode);

		if(respondToCommand(client, commandCode, userid) == -1) return -1;
	}


	return 0;
}

int main(int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];

	initOpenSSL();
	int status = runServer(hostname, port, SERVER_CERTIFICATE, SERVER_PRIVKEY, TRUST_STORE, &handleClient);
	return status;

}
