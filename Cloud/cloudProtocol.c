#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#include "../netbase/netbase.h"
#include "cloudProtocol.h"
#include "database.h"
#include "../User/database.h"

#include <openssl/md5.h>

//the filename we give files as we encrypt them before uploading
#define TEMP_ENCRYPTED_FILENAME "tempEncrypted.file"

#define BUFFER_SIZE 1024
#define MEGABYTE (1024*1024)

#define LIST_FILES_CODE 1
#define UPLOAD_FILE_CODE 2
#define DOWNLOAD_FILE_CODE 3
#define DELETE_FILE_CODE 4

/* Helper function for clientListFiles().  Write the filename
 * of all items in a directory to the given string, separated
 * by newlines. */
int listFiles(char *buffer, int maxLength, int clientid) {
	char dirname[BUFFER_SIZE];
	snprintf(dirname, sizeof(dirname), "./%d/", clientid);
	DIR *dir = opendir(dirname);
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

/*
 * LIST FILES : CLIENT SIDE
 *
 * Handle the client side of the list files funcitonality
 */ 
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

/*
 * LIST FILES : SERVER SIDE
 *
 * Handle the server side of the list files funcitonality
 */ 
int serverListFiles(BIO *conn, int clientid) {
	//send the client a single string listing all files
	//in the folder
	char buffer[BUFFER_SIZE];
	if(listFiles(buffer, sizeof(buffer), clientid) == -1) return -1;

	if(writeString(conn, buffer) < 1) return -1;

	return 1;
}

int clientUploadFile(BIO *conn, char *filename) {
 
	FILE *ifp = fopen(filename, "rb");
	if ( ifp == NULL )  return 5;
	//send the code which causes the server to call serverUploadFile()
	
	
	if(writeInt(conn, UPLOAD_FILE_CODE) == -1) return -1;
	
	//generate key and iv for encryption
	unsigned char *key = randomBytes(32);
	unsigned char *iv = randomBytes(32);
	
	//encrypt the file
	int status = encryptFile(filename, TEMP_ENCRYPTED_FILENAME, key, iv);

	//get digest
	unsigned char hash[MD5_DIGEST_LENGTH];
	status = calculateMD5(TEMP_ENCRYPTED_FILENAME, hash);
	if(status < 0) {
		fprintf(stderr, "Fail to calculate digest in uploadFile()\n");
		return -1;
	}
	
	//store these for later
	addRecord(filename, hash, key, iv);

	//send the fileSize
	int fileSize = sizeOfFile(TEMP_ENCRYPTED_FILENAME);
	if(writeInt(conn, fileSize) == -1) return -1;

	//wait for an int telling us the balance owing
	unsigned int fee = readInt(conn);
	if(fee > 0) {
		printf("Purchase %d more cloud dollar(s) to upload this file.\n", fee);
		return -1;
	}
	else if(fee < 0) return -1;

	printf("ABOUT TO SEND THE FILE\n");
	//send the file
	if(writeFile(conn, TEMP_ENCRYPTED_FILENAME, filename, fileSize) < 1) return -1;

	unlink( TEMP_ENCRYPTED_FILENAME );
	//free and return
	free(key);
	free(iv);

	printf("Client succesfully uploaded the file.\n");
	return 0;
}

int serverUploadFile(BIO *conn, int clientid) {
	//receive the filesize
	int fileSize = readInt(conn);
	if(fileSize == -1) return -1;

	printf("Received filesize %d\n", fileSize);

	//the upload costs $1 per MEGABYTE
	int cost = fileSize / MEGABYTE;
	if(fileSize % MEGABYTE != 0) ++cost;

	//check user has the balance for a file of this size
	int userBalance = getBalance(clientid);
	int response = 0;
	if(userBalance == -1) response = -1;
	else if(userBalance < cost) response = cost - userBalance;
	else response = 0;

	//inform user of whether we are going ahead or not
	int status = writeInt(conn, response);
	if(response != 0) return response;
	if(status < 0) return status;
	
	printf("Going ahead with file transfer.\n");
	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%d/", clientid);
	if(chdir(userDirectory) != 0) {
		perror("serverUploadFile");
		return -1;
	}

	printf("ABOUT TO GET THE FILE\n");

	//receive the file
	status = recvFile(conn);
	if(chdir("../") != 0) {
		perror("serverUploadFile");
		return -1;
	}

	if(status < 1) return -1;
	printf("Server succesfully uploaded the file.\n");
	return 1;
}

int clientDownloadFile(BIO *conn, char *filename, int clientid)  {
	if(writeInt(conn, DOWNLOAD_FILE_CODE) == -1) return -1;
	
	if ( writeString(conn, filename) < 1 ) return -1;
	
	//int fileSize = readInt(conn);
	//if ( fileSize < 0 ) return -1;
	
	int status = recvFile(conn);
	if ( status < 0 ) return -1;
	if ( status == 5 ) return 5;
	
	FILERECORD *r = getRecord(filename);
	
	
	status = decryptFile(TEMP_ENCRYPTED_FILENAME, filename, r->key, r->iv);
	if ( status < 0 ) return -1;
	
	unlink(TEMP_ENCRYPTED_FILENAME);
	
	return 1;
	
}

int serverDownloadFile(BIO *conn, int clientid)  {

	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%d/", clientid);
	if(chdir(userDirectory) != 0) {
		perror("serverDownloadFile");
		return -1;
	}
  
	char filename[BUFFER_SIZE];
	if ( readString( conn, filename, sizeof(filename) ) < 1 ) return -1;
	
	printf("%s\n", filename);
	
	int status = writeFile(conn, filename, TEMP_ENCRYPTED_FILENAME, sizeOfFile(filename) );
	
	if(chdir("../") != 0) {
		perror("serverDownloadFile");
		return -1;
	}
	
	if ( status == 5 ) return 1;
	if ( status < 0 ) return -1;
	return 1;
}

int clientDeleteFile(BIO *conn, char *filename, int clientid)  {
	if(writeInt(conn, DELETE_FILE_CODE) == -1) return -1;
	
	if ( writeString(conn, filename) < 1 ) return -1;
	
	int status = readInt(conn);
	
	if ( status == 5 ) return 5;
	if ( status < 0 ) return -1;
	
	return 0;
	
}

int serverDeleteFile(BIO *conn, int clientid)  {
	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%d/", clientid);
	if(chdir(userDirectory) != 0) {
		perror("serverDeleteFile");
		return -1;
	}
  
	char filename[BUFFER_SIZE];
	if ( readString( conn, filename, sizeof(filename) ) < 1 ) return -1;
	
	int status;
	FILE *ifp = fopen(filename, "rb");
	if ( ifp == NULL )  {
		status = 5;
	}
	else  {
		fclose(ifp);
		unlink(filename);
		status = 0;
	}
	
	if(chdir("../") != 0) {
		perror("serverDeleteFile");
		return -1;
		return -1;
	}
	
	if ( writeInt(conn, status) < 0 ) return -1;
	
	return status;
	
	
}


/* The server receives a command code, branch to the 
 * appropriate part of the protocol */
int respondToCommand(BIO *conn, int code, int clientid) {
	printf("Server received command %d\n", code);
	int status;
	switch(code) {
		case LIST_FILES_CODE:
			status = serverListFiles(conn, clientid);
			break;
		case UPLOAD_FILE_CODE:
			status = serverUploadFile(conn, clientid);
			break;
		case DOWNLOAD_FILE_CODE:
			status = serverDownloadFile(conn, clientid);
			break;
		case DELETE_FILE_CODE:
			status = serverDeleteFile(conn, clientid);
			break;
		default:
			status = 0;
			break;
	}

	return status;
}
