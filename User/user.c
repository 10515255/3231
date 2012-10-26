#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"
#include "database.h"
#include "../Cloud/cloudProtocol.h"

#define MAX_COMMAND_SIZE 512 

#define TRUST_STORE "Certs/trustStore.pem"

int userid;

void stripNewline(char *string) {
	string[strlen(string)-1] = '\0';
}

int handleServer(BIO *server) {
	if(writeInt(server, userid) == -1) return -1;

	char buffer[MAX_COMMAND_SIZE];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		stripNewline(buffer);

		//process the command	
		if(strncmp(buffer, "ls", 2) == 0) {
			printf("LS HIT\n");
			int status = clientListFiles(server);
			printf("Status: %d\n", status);
		}
		else if(strncmp(buffer, "upload ", 7) == 0) {
			printf("UPLOAD HIT\n");
			char *filename = buffer + 7;
			printf("About to send %s\n", filename);
			int status = clientUploadFile(server, filename);
			if ( status == 5 ) printf("File does not exist\n");
			printf("clientUploadFile(): %d\n", status);
		}
		else if (strncmp(buffer, "download ", 9) == 0)  {
			char *filename = buffer + 9;
			int status = clientDownloadFile(server, filename, userid);
			printf("clientDownloadFile(): %d\n", status);
			if ( status == 5 ) printf("File not found. Try ls to check your files.\n");
		}
		else if (strncmp(buffer, "delete ", 7) == 0)  {
			char *filename = buffer + 7;
			int status = clientDeleteFile(server, filename, userid);
			if ( status < 0 || status == 5) printf("File does not exist\n");
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
	//set the global userid
	userid = atoi(argv[5]);

	//connect to the server, then run handleServer() on the resulting connection
	initOpenSSL();
	int status = connectToServer(hostname, port, certFile, privKeyFile, TRUST_STORE, &handleServer);

	return status;
}
