#define _BSD_SOURCE

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
#include "../Bank/dollars.h"

#include <openssl/md5.h>

//the filename we give files as we encrypt them before uploading
#define TEMP_ENCRYPTED_FILENAME "tempEncrypted.file"
#define TEMP_DOLLAR_FILENAME "cloudDollar.file"

#define SERVER_FILE_FOLDER "Users"

#define BUFFER_SIZE 1024
#define MEGABYTE (1024*1024)

#define LIST_FILES_CODE 1
#define UPLOAD_FILE_CODE 2
#define DOWNLOAD_FILE_CODE 3
#define DELETE_FILE_CODE 4
#define VERIFY_FILE_CODE 5
#define REFRESH_HASHES_CODE 6

#define WALLET_BALANCE_CODE 7
#define FILL_WALLET_CODE 8


/* Helper function for clientListFiles().  Write the filename
 * of all items in a directory to the given string, separated
 * by newlines. */
int listFiles(char *buffer, int maxLength, int clientid) {
	char dirname[BUFFER_SIZE];
	snprintf(dirname, sizeof(dirname), "./%s/%d/", SERVER_FILE_FOLDER, clientid);
	DIR *dir = opendir(dirname);
	if(dir == NULL) return -1;

	buffer[0] = '\0';
	struct dirent *entry = NULL;
	while((entry = readdir(dir)) != NULL) {
		if(entry->d_type != DT_REG) continue;//only view regular files
		if(entry->d_name[0] == '.') continue;//don't view hidden files
		//need to fit the name and a newline onto end of our buffer
		int spaceRequired = strlen(entry->d_name) + 2;
		if(spaceRequired > maxLength) break;	
		snprintf(buffer, maxLength, "\t%s\n", entry->d_name);
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
	printf("Your files:\n");
	printf("%s", buffer);
	
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

	/* CALCULATE AND STORE ANY RECORDS OF THIS FILE WE NEED
	 * BEFORE UPLOADING IT */

	FILE *ifp = fopen(filename, "rb");
	if ( ifp == NULL )  return NO_SUCH_FILE;
	
	//generate key and iv for encryption
	unsigned char *key = randomBytes(32);
	unsigned char *iv = randomBytes(32);
	
	//encrypt the file
	int status = encryptFile(filename, TEMP_ENCRYPTED_FILENAME, key, iv);
	if(status == -1) {
		fprintf(stderr, "Failed to encrypt %s in clientUploadFile()\n", filename);
		return -1;
	}

	//we need to store NUM_HASHES salts and digests for later verification
	unsigned char *salts[NUM_HASHES];
	unsigned char *hashes[NUM_HASHES];

	for(int i=0; i<NUM_HASHES; ++i) {
		//generate a random salt
		salts[i] = randomBytes(SALT_LENGTH);
		//compute the digest for the file with that salt
		hashes[i] = calculateMD5(TEMP_ENCRYPTED_FILENAME, salts[i], SALT_LENGTH);
		if(hashes[i] == NULL) {
			fprintf(stderr, "Failed to calculate digest in clientUploadFile()\n");
			return -1;
		}
	}
	
	//store all this data for later
	status = addRecord(filename, 0, hashes, salts, key, iv);
	if(status == -1) {
		fprintf(stderr, "addRecord() failed for in clientUploadFile()\n");
		return -1;
	}
	
	//free the memory we allocated above
	for(int i=0; i < NUM_HASHES; ++i) {
		free(salts[i]);
		free(hashes[i]);
	}
	free(key);
	free(iv);

	/* START THE ACTUAL COMMUNICATION WITH THE SERVER */
	
	//send the code which causes the server to call serverUploadFile()
	if(writeInt(conn, UPLOAD_FILE_CODE) == -1) return -1;

	//send the fileSize
	int fileSize = sizeOfFile(TEMP_ENCRYPTED_FILENAME);
	if(writeInt(conn, fileSize) == -1) return -1;

	printf("NOTE: Original size: %f MB. Encrypted size: %f MB.\n", (double)sizeOfFile(filename)/MEGABYTE, (double)fileSize/MEGABYTE);


	//wait for an int telling us the balance owing
	unsigned int fee = readInt(conn);
	if(fee > 0) {
		printf("Purchase %d more cloud dollar(s) to upload this file.\n", fee);
		removeRecord(filename);
		return -1;
	}
	else if(fee < 0) return -1;

	//send the file
	if(writeFile(conn, TEMP_ENCRYPTED_FILENAME, filename) < 1) return -1;
	unlink( TEMP_ENCRYPTED_FILENAME );
	printf("Succesfully uploaded the file.\n");
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
	snprintf(userDirectory, sizeof(userDirectory), "./%s/%d/", SERVER_FILE_FOLDER, clientid);
	if(chdir(userDirectory) != 0) {
		perror("serverUploadFile");
		return -1;
	}


	//receive the file, save it with whatever name the client uses
	status = recvFile(conn, NULL);
	if(chdir("../../") != 0) {
		perror("serverUploadFile");
		return -1;
	}

	//update their balance
	if(updateBalance(clientid, userBalance - cost) == -1) return -1;

	return 1;
}

/* Download the file with the given name from the server.  If decrypt is 0
 * then the file will not be decrypted, and will be left in TEMP_ENCRYPTED_FILENAME.
 * If decrypt is not 0 then the file will be decrypted according to the clients
 * records and saved under its original name. */
int clientDownloadFile(BIO *conn, char *filename, int decrypt)  {
	//trigger the server to call serverDownloadFile()
	if(writeInt(conn, DOWNLOAD_FILE_CODE) == -1) return -1;
	
	//send the server the filename we want to download
	if ( writeString(conn, filename) < 1 ) return -1;

	int status = readInt(conn);
	if(status == -1) {
		printf("No such file %s\n", filename);
		return 0;
	}
	
	//receive the encrypted file, save to temporary file
	status = recvFile(conn, TEMP_ENCRYPTED_FILENAME);
	if ( status < 0 ) return -1;
	if ( status == 5 ) return 5;

	//if no decryption requested quit early
	if(!decrypt) return 0; 
	

	//otherwise check our records to decrypt this file
	FILERECORD *r = getRecord(filename);
	if(r == NULL) {
		printf("No record stored for this file, so no decryption performed.\n");
		return -1;
	}
	
	//decrypt the file, and save with it's original name
	status = decryptFile(TEMP_ENCRYPTED_FILENAME, filename, r->key, r->iv);
	if ( status < 0 ) return -1;

	unlink(TEMP_ENCRYPTED_FILENAME);
	printf("Successfully downloaded %s\n", filename);
	
	return 0;
	
}

int serverDownloadFile(BIO *conn, int clientid)  {

	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%s/%d/",SERVER_FILE_FOLDER, clientid);
	if(chdir(userDirectory) != 0) {
		perror("serverDownloadFile");
		return -1;
	}
  
	char filename[BUFFER_SIZE];
	if ( readString( conn, filename, sizeof(filename) ) < 1 ) return -1;

	//check the file exists first, and send an int indicating if we continue
	FILE *test =fopen(filename, "r");	
	if(test == NULL) {
		writeInt(conn, -1);
		chdir("../../");
		return 0;
	}
	fclose(test);
	writeInt(conn, 0);
	
	int status = writeFile(conn, filename, TEMP_ENCRYPTED_FILENAME);
	if(chdir("../../") != 0) {
		perror("serverDownloadFile");
		return -1;
	}
	
	if ( status == 5 ) return 1;
	if ( status < 0 ) return -1;
	return 1;
}

int clientDeleteFile(BIO *conn, char *filename)  {
	if(writeInt(conn, DELETE_FILE_CODE) == -1) return -1;
	
	if ( writeString(conn, filename) < 1 ) return -1;
	
	int status = readInt(conn);
	
	if ( status == 5 ) return 5;
	if ( status < 0 ) return -1;

	//remove this file's record from our database
	removeRecord(filename);

	printf("Successfully deleted %s\n", filename);
	
	return 0;
	
}

int serverDeleteFile(BIO *conn, int clientid)  {
	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%s/%d/", SERVER_FILE_FOLDER, clientid);
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
	
	if(chdir("../../") != 0) {
		perror("serverDeleteFile");
		return -1;
	}
	
	if ( writeInt(conn, status) < 0 ) return -1;
	
	return status;
}

int clientVerifyFile(BIO *conn, char *filename) {
	//check our records
	FILERECORD *record = getRecord(filename);
	if(record == NULL) {
		fprintf(stderr, "No records stored for %s\n", filename);
		return -1;
	}

	//see if we have an "unused" salt and digest on record
	int index = record->hashIndex[0];
	if(index == NUM_HASHES) {
		fprintf(stderr, "All stored digests for this file have been consumed.\n");
		fprintf(stderr, "Type \"refresh %s\" to download the file and generate new digests.\n", filename);
		return -1;
	}

	unsigned char *hash = record->hashData[index];
	unsigned char *salt = hash + HASH_LENGTH;

	//send the code which triggers the server to call serverVerifyFile()
	if(writeInt(conn, VERIFY_FILE_CODE) == -1) return -1;

	//send the filename
	if(writeString(conn, filename) < 1) return -1;

	//send the salt
	if(writePacket(conn, (char *)salt, SALT_LENGTH) < 1) return -1;

	//wait for the server to indicate if a digest is coming or not
	int status = readInt(conn);
	//if the file does not exist
	if(status == 5) return 5;
	//if server failed to calculate digest
	if(status == -1) return -1;
	
	//receive the digest
	char serverHash[MD5_DIGEST_LENGTH];
	status = readPacket(conn, serverHash, sizeof(serverHash));
	if(status < 1) return -1;
	
	//check it against our stored digest
	if(memcmp(serverHash, hash, sizeof(serverHash)) != 0) {
		printf("The file digest does not match our records.\n");
	}
	else printf("The file digest matches our records.\n");

	++index;
	printf("You have consumed %d of %d stored digests.\n", index, NUM_HASHES);

	//update the hashIndex for this file
	updateHashIndex(filename, index);	

	return 0;
}

int serverVerifyFile(BIO *conn, int clientid) {
	//receive the filename
	char filename[BUFFER_SIZE];
	if(readString(conn, filename, sizeof(filename)) < 1) return -1;

	//receive the salt
	unsigned char salt[SALT_LENGTH];
	if(readPacket(conn, (char *)salt, SALT_LENGTH) < 1) return -1;

	//navigate to the users directory
	char userDirectory[BUFFER_SIZE];
	snprintf(userDirectory, sizeof(userDirectory), "./%s/%d/", SERVER_FILE_FOLDER, clientid);
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
	
	//calculate a digest 
	unsigned char *digest = calculateMD5(filename, salt, SALT_LENGTH);
	//send -1 if failed to calculate digest
	if(digest == NULL) {
		writeInt(conn, -1);
		return -1;
	}

	//return to main directory
	if(chdir("../../") != 0) {
		perror("serverDeleteFile");
		return -1;
	}

	//send 0 to indicate no failure, and a digest is coming
	if(writeInt(conn, 0) < 1) return -1;

	//send the digest
	if(writePacket(conn, (char *)digest, HASH_LENGTH) < 1) return -1;

	return 0;
}

/* Generate new salt/hash combinations for verification of the given
 * file.  I.e the client can download their file, then call this function
 * to give them another NUM_HASHES new verification calls */
int clientRefreshHashes(BIO *conn, char *filename) {

	//download the file from the server (but dont decrypt it)
	//this saves it as TEMP_ENCRYPTED_FILENAME
	int status = clientDownloadFile(conn, filename, 0);
	if(status != 0) return status;

	//we need to store NUM_HASHES salts and digests for later verification
	unsigned char *salts[NUM_HASHES];
	unsigned char *hashes[NUM_HASHES];

	//get the deatils of this file
	FILERECORD *record = getRecord(filename);
	if(record == NULL) return -1;

	//check the file matches the hashes we have stored
	//(to stop the server switching the file on us as we update the hashes)
	for(int i=0; i < NUM_HASHES; ++i) {
		unsigned char *recordHash = record->hashData[i];
		unsigned char *salt = record->hashData[i] + HASH_LENGTH;

		unsigned char *hash = calculateMD5(TEMP_ENCRYPTED_FILENAME, salt, SALT_LENGTH);
		if(memcmp(recordHash, hash, HASH_LENGTH) != 0) {
			fprintf(stderr, "Mismatching hash for downloaded file during clientRefreshHashes()\n");
			free(hash);
			return -1;
		}
		free(hash);
	}

	//generate new salts and hashes to give us NUM_HASHES more calls to clientVerifyFile
	for(int i=0; i<NUM_HASHES; ++i) {
		//generate a random salt
		salts[i] = randomBytes(SALT_LENGTH);
		//compute the digest for the file with that salt
		hashes[i] = calculateMD5(TEMP_ENCRYPTED_FILENAME, salts[i], SALT_LENGTH);
		if(hashes[i] == NULL) {
			fprintf(stderr, "Failed to calculate digest in clientRefreshHashes()\n");
			return -1;
		}
	}

	//we no longer need the copy we downloaded
	unlink(TEMP_ENCRYPTED_FILENAME);

	//update the record with these new hashes and reset the hashIndex
	status = addRecord(filename, 0, hashes, salts, record->key, record->iv);
	if(status == -1) {
		fprintf(stderr, "Failed to update record for %s in clientRefreshHashes()\n", filename);
		return -1;
	}

	//free the salts and hashes we generated
	for(int i=0; i < NUM_HASHES; ++i) {
		free(salts[i]);
		free(hashes[i]);
	}

	printf("Verified the file (all %d digests match),\n", NUM_HASHES);
	printf("and generated %d new digests.\n", NUM_HASHES);
	
	return 0;	
}

/* Display the amount of money stored in the user's cloud provider account. */
int clientWalletBalance(BIO *conn) {
	//send the code which triggers the server to call serverWalletBalance()
	if(writeInt(conn, WALLET_BALANCE_CODE) == -1) return -1;

	//read the balance back from the server
	int balance = readInt(conn);
	if(balance == -1) {
		fprintf(stderr, "Failed to get balance.\n");
		return -1;
	}
	
	printf("You have %d cloud dollars in your cloud wallet.\n", balance);
	return 0;
}

int serverWalletBalance(BIO *conn, int clientid) {
	//get the balance for this user
	int balance = getBalance(clientid);
	
	//return the balance (which is already -1 if failed)
	if(writeInt(conn, balance) == -1) return -1;

	return 0;
}

/* Add money to the clients cloud account, using the cloud bank dollar. */
int clientAddToWallet(BIO *conn, char *dollarFile, EVP_PKEY *privKey)  
{
	//check if the file is valid
	FILE *test = fopen(dollarFile, "r");
	if(test == NULL) {
		perror(dollarFile);
		return -1;
	}
	fclose(test);

	//the client signs the cloud dollar file
	unsigned int sigLength;
	unsigned char* signature = signFile(dollarFile, privKey, &sigLength);
	if(signature == NULL) {
		fprintf(stderr, "Failed to sign cloud dollar in clientAddToWallet()\n");
		return -1;
	}

	//send the code to make the server call serverAddToWallet()
	if ( writeInt( conn, FILL_WALLET_CODE ) == -1) return -1;
	
	//send the cloud dollar file
	int status = writeFile(conn, dollarFile, dollarFile);
	if ( status < 1 ) return -1;
	
	//send the signature
	status = writePacket(conn, (char *)signature, (int)sigLength );

	//read the int informing us of success / failure
	status = readInt(conn);
	if(status == -1) return -1;
	if(status == -2) {
		printf("That file was not a valid cloud dollar.\n");
		return -1;
	}
	if(status == -3) {
		printf("The signature did not match the file.\n");
		return -1;
	}

	printf("Added %d dollar(s) to your cloud balance.\n", status);
	//delete the cloud dollar file??
	
	return 0;
}

int serverAddToWallet(BIO *conn, int clientid, EVP_PKEY *clientKey, EVP_PKEY *bankKey)  {
	//receive the cloud dollar file
	if(recvFile(conn, TEMP_DOLLAR_FILENAME) == -1) return -1;
	
	//receive the signature
	char signature[BUFFER_SIZE];
	int status = readPacket(conn, signature, sizeof(signature));
	if ( status == -1 ) return -1;
	int sigSize = status;
	
	//verify the cloud dollar is real (signed by the bank and right string)
	int verified = verifyCloudDollar(TEMP_DOLLAR_FILENAME, bankKey); 
	if(verified < 0) {
		printf("\tReceived an INVALID cloud dollar.\n");

		//inform user of probelm
		writeInt(conn, -2);
		return 0;
	}
	else printf("\tRecieved a valid cloud dollar.\n");

	int serial;
	int amount;
	int user;
	status = getDollarData(TEMP_DOLLAR_FILENAME, &serial, &amount, &user);
	
	//verify the user signed the cloud dollar
	verified = verifyFile(TEMP_DOLLAR_FILENAME, (unsigned char*)signature, sigSize, clientKey);
	if(!verified) {
		printf("\tReceived INVALID signature for the cloud dollar.\n");
		//infomr user of promebl
		writeInt(conn, -3);
		return 0;
	}
	else printf("\tReceived a valid signature from %d\n", clientid);

	//all valid, so up their balance
	int balance = getBalance(clientid);
	status = updateBalance(clientid, balance + amount);
	if(status == -1) {
		//inform user
		writeInt(conn, -1);
		return -1;
	}

	//inform user of success
	if(writeInt(conn, amount) == -1) return -1;
	return amount;
}



/* The server receives a command code, branch to the 
 * appropriate part of the protocol */
int respondToCommand(BIO *conn, int code, int clientid, EVP_PKEY *clientKey, EVP_PKEY *bankPublicKey) {
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
		case WALLET_BALANCE_CODE:
			status = serverWalletBalance(conn, clientid);
			break;
		case FILL_WALLET_CODE:
			status = serverAddToWallet(conn, clientid, clientKey, bankPublicKey);
			break;
		default:
			status = 0;
			break;
	}

	return status;
}
