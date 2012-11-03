#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <openssl/md5.h>

#include "../netbase/netbase.h"
#include "cloudProtocol.h"
#include "database.h"
#include "../User/database.h"

#include <openssl/md5.h>

//the filename we give files as we encrypt them before uploading
#define TEMP_ENCRYPTED_FILENAME "tempEncrypted.file"

#define USER_FILE_FOLDER "Files"

#define BUFFER_SIZE 1024
#define MEGABYTE (1024*1024)

#define LIST_FILES_CODE 1
#define UPLOAD_FILE_CODE 2
#define DOWNLOAD_FILE_CODE 3
#define DELETE_FILE_CODE 4
#define VERIFY_FILE_CODE 5
#define WALLET_CODE 6

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
	if ( ifp == NULL )  return NO_SUCH_FILE;
	//send the code which causes the server to call serverUploadFile()
	if(writeInt(conn, UPLOAD_FILE_CODE) == -1) return -1;
	
	//generate key and iv for encryption
	unsigned char *key = randomBytes(32);
	unsigned char *iv = randomBytes(32);
	
	//encrypt the file
	int status = encryptFile(filename, TEMP_ENCRYPTED_FILENAME, key, iv);

	//get digest
	unsigned char hash[MD5_DIGEST_LENGTH];
	status = calculateMD5(TEMP_ENCRYPTED_FILENAME, hash, NULL, 0);
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

	//send the file
	if(writeFile(conn, TEMP_ENCRYPTED_FILENAME, filename) < 1) return -1;

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
	
	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%d/", clientid);
	if(chdir(userDirectory) != 0) {
		perror("serverUploadFile");
		return -1;
	}


	//receive the file, save it with whatever name the client uses
	status = recvFile(conn, NULL);
	if(chdir("../") != 0) {
		perror("serverUploadFile");
		return -1;
	}

	if(status < 1) return -1;
	return 1;
}

int clientDownloadFile(BIO *conn, char *filename, int clientid)  {
	//trigger the server to call serverDownloadFile()
	if(writeInt(conn, DOWNLOAD_FILE_CODE) == -1) return -1;
	
	//send the server the filename we want to download
	if ( writeString(conn, filename) < 1 ) return -1;
	
	//receive the encrypted file, save to temporary file
	int status = recvFile(conn, TEMP_ENCRYPTED_FILENAME);
	if ( status < 0 ) return -1;
	if ( status == 5 ) return 5;
	
	FILERECORD *r = getRecord(filename);
	if(r == NULL) {
		printf("No record stored for this file, so no decryption performed.\n");
		return 1;
	}
	
	//decrypt the file, and save with it's original name
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
	
	
	int status = writeFile(conn, filename, TEMP_ENCRYPTED_FILENAME);
	
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

	//remove this file's record from our database
	removeRecord(filename);
	
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
	}
	
	if ( writeInt(conn, status) < 0 ) return -1;
	
	return status;
}

int clientVerifyFile(BIO *conn, char *filename, int clientid) {
	if(writeInt(conn, VERIFY_FILE_CODE) == -1) return -1;

	//send the filename
	if(writeString(conn, filename) < 1) return -1;

	int status = readInt(conn);
	//if the file does not exist
	if(status == 5) return 5;
	//if server failed to calculate hash
	if(status == -1) return -1;
	
	//receive a digest
	char digest[MD5_DIGEST_LENGTH];
	status = readPacket(conn, digest, sizeof(digest));
	if(status < 1) return -1;
	
	//check it against our stored digest
	FILERECORD *record = getRecord(filename);
	if(record == NULL) return -1;

	if(memcmp(digest, record->hash, sizeof(digest)) != 0) {
		printf("The file digest does not match our records.\n");
	}
	else printf("The file digest matches our records.\n");

	return 0;
}

int serverVerifyFile(BIO *conn, int clientid) {
	//receive the filename
	char filename[BUFFER_SIZE];
	if(readString(conn, filename, sizeof(filename)) < 1) return -1;

	//navigate to the users directory
	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%d/", clientid);
	if(chdir(userDirectory) != 0) {
		perror("serverDeleteFile");
		return -1;
	}

	//open the file or send 5 if file does not exits
	FILE *ifp = fopen(filename, "rb");
	if(ifp == NULL) {
		if(writeInt(conn, 5) < 1) return -1;
		return 5; 
	}
	fclose(ifp);
	
	//calculate a digest OR send -1 if error
	unsigned char digest[MD5_DIGEST_LENGTH];
	int status = calculateMD5(filename, digest, NULL, 0);
	if(status == -1) {
		writeInt(conn, -1);
		return -1;
	}

	if(chdir("../") != 0) {
		perror("serverDeleteFile");
		return -1;
	}

	//send 0 to indicate no failure, and a digest is coming
	if(writeInt(conn, 0) < 1) return -1;

	//send the digest
	status = writePacket(conn, (char *)digest, sizeof(digest));
	if(status < 1) return -1;
	return status;
}

/*
int clientWallet(BIO *conn, char *filename, int clientid, EVP_PKEY *privKey)  {
	if ( writeInt( conn, WALLET_CODE ) == -1) return -1;
	
	writeString(conn, filename);
	
	unsigned int sigLength;
	unsigned char* signature = signFile(filename, privKey, &sigLength);
	
	int status = writeFile(conn, filename, filename);
	if ( status < 1 ) return -1;
	
	status = writePacket(conn, (char *)signature, (int)sigLength );
	
	if ( status < 1 ) return -1;
	

}
*/

/*
int serverWallet(BIO *conn, int clientid)  {

	int status = recvFile(conn);
	if ( status < 1 ) return -1;
	
	char filename[BUFFER_SIZE];
	readString(conn, filename, sizeof(filename));
	
	char buffer[BUFFER_SIZE];
	
	status = readPacket(conn, buffer, sizeof(buffer));
	if ( status == -1 ) return -1;
	
	int verified = verifyFile( filename, (unsigned char*)buffer, 256 );
	if ( verified)  {
	    FILE *fp = fopen(filename, "r");
	    if ( fp == NULL ) return -1;
	    
	    char line[BUFFER_SIZE];
	    fgets(line, sizeof(line), fp);
	    fgets(line, sizeof(line), fp);
	    fgets(line, sizeof(line), fp);
	    
	 
	    int amount;
	    int numMatched = sscan( line, "Amount: %d", &amount);
	    
	    if ( numMatched != 1 ) return -1;
	    else updateBalance(userid, getBalance(userid) + amount);
	    
	    return 0;
	}
	
  
}
*/


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
		case VERIFY_FILE_CODE:
			status = serverVerifyFile(conn, clientid);
			break;
		/*case WALLET_CODE:
			status = serverWallet(conn, clientid);
			break;
		*/
		default:
			status = 0;
			break;
	}

	return status;
}
