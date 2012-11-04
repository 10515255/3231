//so we can truncate the file in removeRecord()
#define _BSD_SOURCE
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_LINE_LENGTH 1024 

#include "../netbase/netbase.h"
#include "database.h"

char *dbFilename = "files.db";

/* Write the details of a file we have uploaded to file. */
int writeRecord(FILE *output, char *filename, unsigned char hashIndex, unsigned char **hashes, unsigned char **salts, unsigned char *key, unsigned char *iv) {
	//create a lump of size FILENAME_LENGTH, fill with 0's
	char fileLump[FILENAME_LENGTH];
	memset(fileLump, 0, FILENAME_LENGTH);
	strncpy(fileLump, filename, sizeof(fileLump));

	//write the filename to file
	int numWritten = fwrite(fileLump, 1, FILENAME_LENGTH, output);
	if(numWritten != FILENAME_LENGTH) {
		perror("writeRecord");
		return -1;
	}

	//write the hashIndex (number of hashes we have used up)
	//note the argument hashIndex is NOT a pointer
	numWritten = fwrite(&hashIndex, 1, HASH_INDEX_LENGTH, output);
	if(numWritten != HASH_INDEX_LENGTH) {
		perror("writeRecord");
		return -1;
	}
	
	//write the hash data to file
	for(int i=0; i < NUM_HASHES; ++i) {
		//write the hash
		numWritten = fwrite(hashes[i], 1, HASH_LENGTH, output);
		if(numWritten != HASH_LENGTH) {
			perror("writeRecord");
			return -1;
		}

		//then the salt which preceded the file data
		numWritten = fwrite(salts[i], 1, SALT_LENGTH, output);
		if(numWritten != HASH_LENGTH) {
			perror("writeRecord");
			return -1;
		}
	}

	//write the key
	numWritten = fwrite(key, 1, KEY_LENGTH, output);
	if(numWritten != KEY_LENGTH) {
		perror("writeRecord");
		return -1;
	}

	//write the iv
	numWritten = fwrite(iv, 1, KEY_LENGTH, output);
	if(numWritten != KEY_LENGTH) {
		perror("writeRecord");
		return -1;
	}
	
	return 0;
}

FILERECORD *readRecord(FILE *input) {
	static FILERECORD record;
	//read in the filename
	int numRead = fread(record.filename, 1, FILENAME_LENGTH, input);
	if(numRead != FILENAME_LENGTH) {
		//return NULL silently if EOF on this first read
		//lets use readRecord until it returns NULL without getting
		//error messages
		if(feof(input)) return NULL;
		perror("readRecord");
		return NULL;
	}

	//read the hashIndex
	numRead = fread(record.hashIndex, 1, HASH_INDEX_LENGTH, input);
	if(numRead != HASH_INDEX_LENGTH) {
		perror("readRecord");
		return NULL;
	}

	//read in the hash data
	for(int i=0; i < NUM_HASHES; ++i) {
		//read this hash
		numRead = fread(record.hashData[i], 1, HASH_LENGTH, input);
		if(numRead != HASH_LENGTH) {
			perror("readRecord");
			return NULL;
		}

		//read the corresponding salt
		numRead = fread(record.hashData[i] + HASH_LENGTH, 1, SALT_LENGTH, input);
		if(numRead != HASH_LENGTH) {
			perror("readRecord");
			return NULL;
		}
	}

	//read the key
	numRead = fread(record.key, 1, KEY_LENGTH, input);
	if(numRead != KEY_LENGTH) {
		perror("readRecord");
		return NULL;
	}

	//read the iv
	numRead = fread(record.iv, 1, KEY_LENGTH, input);
	if(numRead != KEY_LENGTH) {
		perror("readRecord");
		return NULL;
	}

	return &record;
}

int addRecord(char *filename, unsigned char hashIndex, unsigned char **hashes, unsigned char **salts, unsigned char *key, unsigned char *iv) {
	FILE *db = fopen(dbFilename, "rb+");
	if(db == NULL) {
		perror("addRecord");
		return -1;
	}

	//see if a record for this file already exits and overwrite it
	while(1) {
		FILERECORD *record = readRecord(db);
		if(record == NULL) break;

		if(strcmp(record->filename, filename) == 0) {
			//jump back to start of record and overwrite
			if(fseek(db, -RECORD_LENGTH, SEEK_CUR) == -1) {
				perror("fseek failed in addRecord");
				fclose(db);
				return -1;
			}

			//overwrite and exit
			int status = writeRecord(db, filename, hashIndex, hashes, salts, key, iv);
			fclose(db);
			if(status < 0) return status;
			return 0;
		}
	}
	fclose(db);

	//no existing record, add a new one at the end of the file
	db = fopen(dbFilename, "ab");
	if(db == NULL) {
		perror("fopen failed");
		return -1;
	}

	int status = writeRecord(db, filename, hashIndex, hashes, salts, key, iv);
	fclose(db);
	if(status < 0) return status;
	return 0;
}

int updateHashIndex(char *filename, unsigned char hashIndex) {
	FILE *db = fopen(dbFilename, "rb+");
	if(db == NULL) {
		perror("updateHashIndex()");
		return -1;
	}

	FILERECORD *record;
	while((record = readRecord(db)) != NULL) {
		if(strcmp(record->filename, filename) == 0) {
			//jump to the hashIndex member
			if(fseek(db, -RECORD_LENGTH + HASH_INDEX_OFFSET, SEEK_CUR) == -1) {
				perror("fseek() failed in updateHashIndex()");
				fclose(db);
				return -1;
			}

			//update the hash index
			int numWritten = fwrite(&hashIndex, 1, 1, db);
			if(numWritten != 1) {
				perror("updateHashIndex()\n");
				fclose(db);
				return -1;
			}
			break;
		}
	}

	fclose(db);
	return 0;
}
	

int removeRecord(char *targetFilename) {
	//open the database
	FILE *db = fopen(dbFilename, "rb+");
	if(db == NULL) {
		perror("removeRecord()");
		return -1;
	}

	//search for the record with the given filename
	FILERECORD *record = NULL;
	while((record = readRecord(db)) != NULL) {
		if(strcmp(record->filename, targetFilename) == 0) {
			//remember the target record's position
			long targetPosition = ftell(db) - RECORD_LENGTH;

			//jump to the last record in the file
			fseek(db, -RECORD_LENGTH, SEEK_END);
			long cutoff = ftell(db);

			//grab this record's bytes 
			unsigned char lastRecord[RECORD_LENGTH];
			int numRead = fread(lastRecord, 1, RECORD_LENGTH, db);
			if(numRead != RECORD_LENGTH) {
				perror("removeRecord()");
				fclose(db);
				return -1;
			}

			//write them over the record we are removing 
			fseek(db, targetPosition, SEEK_SET);
			int numWritten = fwrite(lastRecord, 1, RECORD_LENGTH, db);
			fclose(db);

			if(numWritten != RECORD_LENGTH) {
				perror("removeRecord()");
				return -1;
			}

			//truncate the (now duplicated) last record off the end of the file
			if(truncate(dbFilename, cutoff) == -1) {
				perror("removeRecord()");
				return -1;
			}
			return 0;
		}
	}

	//the record wasn't in the file
	fclose(db);
	return 0;
}

FILERECORD *getRecord(char *targetFilename) {
	FILE *db = fopen(dbFilename, "rb");
	if(db == NULL) {
		perror("getRecord");
		return NULL;
	}

	FILERECORD *record = NULL;
	while((record = readRecord(db)) != NULL) {
		if(strcmp(record->filename, targetFilename) == 0) {
			fclose(db);
			return record; 
		}
	}
	fclose(db);
	fprintf(stderr, "getRecord() couldn't find %s\n", targetFilename);
	return NULL;
}

void printHash(unsigned char *hash) {
	for(int i=0; i<HASH_LENGTH; ++i) {
		printf("%02x", hash[i]);
	}
}

void printKey(unsigned char *key) {
	for(int i=0; i < KEY_LENGTH; ++i) {
		printf("%02x", key[i]);
	}
}

int printDatabase() {
	FILE *database = fopen(dbFilename, "rb");
	if(database == NULL) {
		perror("printDatabase()");
		return -1;
	}

	FILERECORD *record;
	while((record = readRecord(database)) != NULL) {
		printf("%s\n", record->filename);	
		printf("%u of %d hashes consumed.\n", record->hashIndex[0], NUM_HASHES);
		for(int i=0; i<NUM_HASHES; ++i) {
			printf("Hash: ");
			printHash(record->hashData[i]);
			printf(" Salt: ");
			printHash(record->hashData[i] + HASH_LENGTH);
			printf("\n");
		}
		printf("Key: ");
		printKey(record->key);
		putchar('\n');
		printf("IV: ");
		printKey(record->iv);
		putchar('\n');
		putchar('\n');
	}

	fclose(database);
	return 0;
}



/*
int main(int argc, char **argv) {
	if(argc < 3) {
		printDatabase();
		exit(EXIT_FAILURE);
	}
	char *command = argv[1];
	char *filename = argv[2]; 

	if(strcmp(command, "add") == 0) {
		unsigned char *salts[NUM_HASHES];
		unsigned char *hashes[NUM_HASHES];

		for(int i=0; i< NUM_HASHES; ++i) {
			//generate a random salt
			salts[i] = randomBytes(SALT_LENGTH);
			//calculate hash and store in hashes[i]
			hashes[i] = calculateMD5(filename, salts[i], SALT_LENGTH);
		}

		//generate key and iv
		unsigned char *key = randomBytes(KEY_LENGTH);
		unsigned char *iv = randomBytes(KEY_LENGTH);

		addRecord(filename, 0, hashes, salts, key, iv);

		for(int i=0; i<NUM_HASHES; ++i) {
			free(salts[i]);
		}
		free(key);
		free(iv);
	}
	else if(strcmp(command, "rm") == 0) {
		removeRecord(filename);
	}
	else if(strcmp(command, "inc") == 0) {
		updateHashIndex(filename, 7);
	}

}
*/
