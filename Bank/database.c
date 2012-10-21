/* Keep track of users, their public keys, their bank balance and any
 * outstanding cheques.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "database.h"

#define MAX_LINE_LENGTH 64

/* An array of pointers our users. */
USER **users;
int numUsers;


int loadUsers(char *usersFile) {
	FILE *ifp = fopen(usersFile, "r");
	if(ifp == NULL) {
		perror("loadUsers");
		return -1;
	}
	
	numUsers = -1;
	int matched = fscanf(ifp, "%d", &numUsers);
	if(matched != 1) {
		perror("loadUsers");
		return -2;
	}
	if(numUsers < 0) {
		return -3;
	}

	users = malloc(sizeof(USER *) * numUsers);
	if(users == NULL) {
		perror("loadUsers");
		exit(EXIT_FAILURE);
	}
	for(int i=0; i<numUsers; ++i) {
		users[i] = malloc(sizeof(USER));
		if(users[i] == NULL) {
			perror("loadUsers");
			exit(EXIT_FAILURE);
		}
	}

	for(int i=0; i<numUsers; ++i) {
		int matched = fscanf(ifp, "%d %d", &(users[i]->userid), &(users[i]->balance));
		if(matched != 2) {
			perror("loadUsers");
			return -4;
		}
	}
	
	return 0;
}

int addSerial(char *serialFile, int serial) {
	FILE *ofp = fopen(serialFile, "a"); 
	if(ofp == NULL) {
		perror("addSerial");
		return -1;
	}

	fprintf(ofp, "%d\n", serial);
	fclose(ofp);

	return 0;
}

int removeSerial(char *serialFile, int targetSerial) {
	FILE *ifp = fopen(serialFile, "r");
	if(ifp == NULL) {
		perror("removeSerial");
		return -2;
	}

	FILE *ofp = fopen("temp.j", "w");
	if(ofp == NULL) {
		perror("removeSerial");
		return -3;
	}

	char line[MAX_LINE_LENGTH];
	bool foundSerial = false;
	while(fgets(line, sizeof(line), ifp) != NULL) {
		int serial; 
		int matched = sscanf(line, "%d", &serial);
		if(matched != 1) {
			perror("removeSerial");
			return -4;
		}

		if(serial != targetSerial) {
			fprintf(ofp, "%s", line);
		} 
		else {
			foundSerial = true;
		}
	}

	fclose(ifp);
	fclose(ofp);

	remove(serialFile);	
	int status = rename("temp.j", serialFile);
	if(status < 0) {
		perror("removeSerial");
		return -5;
	}

	if(foundSerial) return 0;
	
	return -1;
}

int queryBalance(int id) {
	for(int i=0; i<numUsers; i++) {
		if(users[i]->userid == id) {
			return users[i]->balance;
		}
	}

	fprintf(stderr, "queryBalance: No user with id %d\n", id);
	return -1;
}

int main(int argc, char **argv)
{
	if(argc < 2) {
		printf("Insufficient arguments.\n");
	}
	loadUsers(argv[1]);

	addSerial("serials.txt", 1);
	addSerial("serials.txt", 2);
	addSerial("serials.txt", 3);
	addSerial("serials.txt", 4);

	removeSerial("serials.txt", 2);
}
