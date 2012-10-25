#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"
#include "database.h"
#include "../Cloud/cloudProtocol.h"

#define MAX_COMMAND_SIZE 512 

void stripNewline(char *string) {
	string[strlen(string)-1] = '\0';
}

int listFiles(BIO *server) {
	int status = writeString(server, "ls");
	if(status < 1) {
		printf("writeString() faild in listFiles()\n");
	}

	char response[1024];
	status = readString(server, response, sizeof(response));
	if(status < 1) {
		printf("readString() failed in listFiles()\n");
	}

	printf("%s\n", response);
	return 0;
}

int uploadFile(BIO *server, char *command) {
	char *filename = command;
	unsigned int fileSize = sizeOfFile(filename);
	//build the server command
	char serverCommand[MAX_COMMAND_SIZE];
	snprintf(serverCommand, sizeof(serverCommand), "filesize "); 
	snprintf(serverCommand + strlen("filesize "), sizeof(serverCommand) - strlen("filesize "), "%d", fileSize);
	int status = writeString(server, serverCommand);
	if(status < 1) {
		fprintf(stderr, "writeString() failed in uploadFile()\n");
		return -1;
	}

	//wait for an int telling us the balance owing
	unsigned int fee = readInt(server);
	if(fee != 0) {
		printf("Insufficient funds: Purchase %u more cloud dollar(s) to upload this file.\n", fee);
		return 0;
	}

	//generate key and iv for encryption
	unsigned char *key = randomBytes(32);
	unsigned char *iv = randomBytes(32);
	
	//load the file
	unsigned char *file = loadFile(filename, &fileSize);
	//encrypt the file
	int cipherLength; 
	unsigned char *ciphertext  = encryptData(file, fileSize, &cipherLength, key, iv);
	if(ciphertext == NULL) {
		fprintf(stderr, "Encryption failed in uploadFile\n");
		return -1;
	}

	//get digest
	unsigned char hash[MD5_DIGEST_LENGTH];
	status = calculateMD5(ciphertext, cipherLength, hash);
	if(status < 0) {
		fprintf(stderr, "Fail to calculate digest in uploadFile()\n");
		return -1;
	}
	
	//store these for later
	addRecord(filename, hash, key, iv);

	//send the file
	status = writePacket(server, filename, strlen(filename));
	if(status < 0) {
		fprintf(stderr, "Failed to send filename in uploadFile()\n");
		return -1;
	}
	status = writePacket(server, (char *)ciphertext, cipherLength);
	if(status < 0) {
		fprintf(stderr, "Failed to send file in uploadFile()\n");
		return -1;
	}

	//free and return
	free(key);
	free(iv);
	free(ciphertext);

	return 0;
}

int handleServer(BIO *server) {
	char buffer[MAX_COMMAND_SIZE];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		stripNewline(buffer);

		//process the command	
		if(strncmp(buffer, "ls", 2) == 0) {
			printf("LS HIT\n");
			writeInt(server, LIST_FILES_CODE);
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
	char *trustStore = argv[5];

	//connect to the server, then run handleServer() on the resulting connection
	initOpenSSL();
	int status = connectToServer(hostname, port, certFile, privKeyFile, trustStore, &handleServer);

	return status;
}
