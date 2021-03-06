#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"
#include "database.h"
#include "../Cloud/cloudProtocol.h"

#define MAX_COMMAND_SIZE 1024 

#define TRUST_STORE "Certs/trustStore.pem"

int userid;
EVP_PKEY *privKey;

void stripNewline(char *string) {
	string[strlen(string)-1] = '\0';
}

int handleServer(BIO *server) {
	if(writeInt(server, userid) == -1) return -1;

	printf("You are connect to the CLOUD PROVIDER\n");

	char buffer[MAX_COMMAND_SIZE];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		stripNewline(buffer);

		//process the command	
		if(strncmp(buffer, "ls", 2) == 0) {
			clientListFiles(server);
		}
		else if(strncmp(buffer, "upload ", 7) == 0) {
			char *filename = buffer + 7;
			int status = clientUploadFile(server, filename);
			if ( status == 5 ) printf("File does not exist\n");
		}
		else if (strncmp(buffer, "download ", 9) == 0)  {
			char *filename = buffer + 9;
			int status = clientDownloadFile(server, filename, 1);
			if ( status == 5 ) printf("File not found. Try ls to check your files.\n");
		}
		else if(strncmp(buffer, "verify ", 7) == 0) {
			char *filename = buffer + 7;
			clientVerifyFile(server, filename);
		}
		else if (strncmp(buffer, "delete ", 7) == 0)  {
			char *filename = buffer + 7;
			int status = clientDeleteFile(server, filename);
			if ( status < 0 || status == 5) printf("File does not exist\n");
		}
		else if(strncmp(buffer, "refresh ", 8) == 0) {
			char *filename = buffer + 8;
			clientRefreshHashes(server, filename);
		}
		else if(strcmp(buffer, "balance") == 0) {
			clientWalletBalance(server);
		}
		else if (strncmp(buffer, "wallet ", 7) == 0)  {
			char *filename = buffer + 7;
			clientAddToWallet(server, filename, privKey);
		}
		else if(strcmp(buffer, "quit") == 0) {
			break;
		}
		else {
			printf("Invalid Command\n");
			writeInt(server, 0);
			continue;
		}

		/*
		int status = readString(server, buffer, sizeof(buffer));
		if(status < 1) {
			printf("Error by readString() in handleServer()\n");
			return -1;
		}
		*/
		printf("**********************\n");
	}

	return 0;
}


int main(int argc, char **argv) {
	if(argc < 6) {
		fprintf(stderr, "Expected a hostname, port, certificate, private key and userid\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];
	char *certFile = argv[3];
	char *privKeyFile = argv[4];
	privKey = loadPrivateKey(privKeyFile);
	//set the global userid
	userid = atoi(argv[5]);

	//connect to the server, then run handleServer() on the resulting connection
	initOpenSSL();
	int status = connectToServer(hostname, port, certFile, privKeyFile, TRUST_STORE, &handleServer);

	return status;
}
