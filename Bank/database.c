/* Keep track of users, their public keys, their bank balance and any
 * outstanding cheques.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "database.h"

#define MAX_LINE_LENGTH 64

/* Only used internally to this file at the moment */
typedef struct {
	int id;
	int balance;
} USER;

/* The file which acts as a database for customers and their information. */
char *usersFilename = "users.txt";
/* The file which acts as a database for serial numbers of issued bank notes */
char *serialsFilename = "serials.txt";

char *tempFilename = "temp.tmp";

/* Remove the line in the file which has the given number
 * at the front of the line */
int removeLine(char *filename, int targetNumber) {
	FILE *ifp = fopen(filename, "r");
	if(ifp == NULL) {
		perror("removeLine");
		return -1;
	}

	FILE *ofp = fopen(tempFilename, "w");
	if(ofp == NULL) {
		perror("removeLine");
		return -1;
	}

	char line[MAX_LINE_LENGTH];
	bool foundLine = false;
	while(fgets(line, sizeof(line), ifp) != NULL) {
		int serial; 
		int matched = sscanf(line, "%d", &serial);
		if(matched != 1) {
			perror("removeLine");
			return -1;
		}

		//print out all lines except that which begins with the target number
		if(serial != targetNumber) {
			fprintf(ofp, "%s", line);
		} 
		else {
			foundLine = true;
		}
	}

	//close all files and rename back to original filename
	fclose(ifp);
	fclose(ofp);
	remove(filename);	
	int status = rename(tempFilename, filename);
	if(status < 0) {
		perror("removeNumber");
		return -1;
	}

	if(foundLine) return 0;
	return -1;
}


/* Add the given serial number to the serials file */
int addSerial(int serial) {
	FILE *ofp = fopen(serialsFilename, "a"); 
	if(ofp == NULL) {
		perror("addSerial");
		return -1;
	}

	fprintf(ofp, "%d\n", serial);
	fclose(ofp);

	return 0;
}

/* Remove the given serial number from the serials file */
int removeSerial(int targetSerial) {
	return removeLine(serialsFilename, targetSerial);
}

/* Read a users info from a line in the given file. */
USER *readUser(FILE *userFile) {
	//static user here, fill it and return pointer to it
	static USER user;

	char line[MAX_LINE_LENGTH];
	if(fgets(line, sizeof(line), userFile) == NULL) return NULL;
	
	int numMatched = sscanf(line, "%d %d", &user.id, &user.balance);
	if(numMatched != 2) {
		fprintf(stderr, "sscanf failed in readUser() on the line:\n");
		fprintf(stderr, "%s", line);
		return NULL;
	}
	return &user;
}

/* Write a users info to the given file stream */
void writeUser(FILE *userFile, USER *user) {
	fprintf(userFile, "%d %d\n", user->id, user->balance);
}

/* Load the user with the given id into a statically allocated USER struct
 * and return a pointer to it */
USER *getUser(int targetID) {
	//load the users file
	FILE *usersFile = fopen(usersFilename, "r");
	if(usersFile == NULL) {
		perror("getBalance()");
		return NULL;
	}

	//read the file until we find this users line
	char line[MAX_LINE_LENGTH];
	USER *user;
	while( (user = readUser(usersFile)) != NULL ) {
		if(user->id == targetID) {
			fclose(usersFile);
			return user;
		}
	}

	//no user with the given id on file
	fprintf(stderr, "getUser() called on non-existant user %u\n", targetID);
	fclose(usersFile);
	return NULL;
}

int removeUser(int targetID) {
	return removeLine(usersFilename, targetID);
}

int addUser(int userid, int balance) {
	//ensure not already user with this id
	USER *u = getUser(userid);
	if(u != NULL) return -1;

	FILE *ofp = fopen(usersFilename, "a");
	if(ofp == NULL) return -1;
	fprintf(ofp, "%d %d\n", userid, balance);
	fclose(ofp);
}

int getBalance(int id) {
	USER *user = getUser(id);
	if(user != NULL) return user->balance;
	
	return -1;
}

// balance is the new balance
int updateBalance(int id, int balance) {
	USER *user = getUser(id);
	if(user == NULL) return -1;

	removeUser(id);
	user->balance = balance;
	if(addUser(user->id, user->balance) == -1) return -1;

	return 0;
}
