#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>

#include "../netbase/netbase.h"

#define READ_BUF_SIZE 1024 
#define MAX_LS_OUTPUT 1024


/* Return to the client a list of all files in the directory,
 * as a single string (entries separated by newlines) */
int ls(BIO *client) {
	DIR *dir = opendir("./");
	if(dir == NULL) {
		fprintf(stderr, "Could not list the directory.\n");
		return -1;
	}

	char output[MAX_LS_OUTPUT];
	output[0] = '\0';
	int space = sizeof(output);
	struct dirent *entry = NULL;
	//need to explicitly check errno before and after to detect error?
	while((entry = readdir(dir)) != NULL) {
		if(space < strlen(entry->d_name)) break;
		strncat(output, entry->d_name, space);
		space -= strlen(entry->d_name);
		strncat(output, "\n", space);
		--space;
	}
	int status = writeString(client, output);
	closedir(dir);

	if(status < 1) return status;
	return 1;
}

int retrieve(BIO *client, char *filename) {
	FILE *ifp = fopen(filename, "rb");
	if(ifp == NULL) return -1;

	int status = sendFile(client, ifp, "requestedFile.file");
	return status;
}

int respondToRequest(BIO *client, char *request) {

		char *reply = "Unexpected command.\n";
		if(strcmp("ls\n", request) == 0) {
			int status = ls(client);
			return status;
		}
		else if(strcmp("cd\n", request) == 0) {
			reply = "You want to change directory?\n";
		}
		else if(strncmp("grab ", request, 5) == 0) {
			char *filename = request + 5;
			//overwrite the newline
			filename[strlen(filename)-1] = '\0';
			int status = retrieve(client, filename);
			return status;
		}

		int status = writeString(client, reply);
		return status;
}

/* A simple handler for a client connection. */
int listenToClient(BIO *client) {

	char buffer[READ_BUF_SIZE];
	while(1) {
		//read into our buffer, leave room for terminal
		int numRead = readPacket(client, buffer, sizeof(buffer));
		if(numRead < 1) {
			if(numRead == 0) printf("The client disconnected.\n");
			else printf("Error %d from readPacket()\n", numRead); 
			return numRead;
		}
		//really got to add a "sendString" which just delegates
		//to sendPacket, but includes the terminal char
		buffer[numRead] = '\0';
		printf("Client: %s", buffer);

		int status = respondToRequest(client, buffer);
		if(status < 1) {
			printf("Error %d from respondToRequest()\n", status);
			return status;
		}
	}

	return 1;
}

int main(int argc, char **argv) {
	//grab any arguments char *hostname = NULL;
	if(argc < 2 || argc > 3) {
		printf("Usage:\n");
		printf(">server hostname port\n");
		printf(">server port\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = (argc == 3) ? argv[1] : NULL;
	char *port = (argc == 3) ? argv[2] : argv[1];

	//start the server listening
	initOpenSSL();
	runServer(hostname, port, &listenToClient);

	exit(EXIT_SUCCESS);

}
