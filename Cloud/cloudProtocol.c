#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>

#include "../netbase/netbase.h"
#include "cloudProtocol.h"

#define BUFFER_SIZE 1024

#define LIST_FILES_CODE 1

/* Write filenames from the current directory to the given
 * string, each on a line of their own. */
int listFiles(char *buffer, int maxLength) {
	DIR *dir = opendir("./");
	if(dir == NULL) return -1;

	buffer[0] = '\0';
	struct dirent *entry = NULL;
	while((entry = readdir(dir)) != NULL) {
		//need to fit the name and a newline onto end of our buffer
		int spaceRequired = strlen(entry->d_name) + 1;
		if(spaceRequired > maxLength) break;	
		snprintf(buffer, maxLength, "%s\n", entry->d_name);
		maxLength -= spaceRequired;
		buffer += spaceRequired;
	}

	closedir(dir);

	return 0;
}


int clientListFiles(BIO *conn) {
	//send the code which causes the server to call serverListFiles() */
	if(writeInt(conn, LIST_FILES_CODE) == -1) return -1;

	//catch the server's response, a single string listing all files
	//from the folder
	char buffer[BUFFER_SIZE];
	if(readPacket(conn, buffer, sizeof(buffer)) < 1) return -1;

	//display the file listing
	printf("%s\n", buffer);
	
	return 1;
}

int serverListFiles(BIO *conn) {
	//send the client a single string listing all files
	//in the folder
	char buffer[BUFFER_SIZE];
	if(listFiles(buffer, sizeof(buffer)) == -1) return -1;

	if(writeString(conn, buffer) < 1) return -1;

	return 1;
	
}

/* The server receives a command code, branch to the 
 * appropriate part of the protocol */
int respondToCommand(BIO *conn, int code) {
	printf("Server received command %d\n", code);
	int status;
	switch(code) {
		case LIST_FILES_CODE:
			status = serverListFiles(conn);
			break;
		default:
			status = 0;
			break;
	}

	return status;
}
