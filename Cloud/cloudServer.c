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

	//load their public key
	char userKeyFilename[BUFFER_SIZE];
	snprintf(userKeyFilename, sizeof(userKeyFilename), "Certs/%dPublicKey.pem", userid);
	EVP_PKEY *userKey = loadPublicKey(userKeyFilename);
	if(userKey == NULL) {
		fprintf(stderr, "Failed to load public key %s\n", userKeyFilename);
		return -1;
	}

	/* Accept commands codes from the client program to determine which 
	 * functionality of the protocol is being initiate. */
	while(1) {
		int commandCode = readInt(client);
		if(commandCode == -1) return -1;

		if(respondToCommand(client, commandCode, userid, userKey) == -1) return -1;
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
