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

int writeRecord(FILE *output, char *filename, unsigned char *hash, unsigned char *key, unsigned char *iv) {
	//create a lump of size FILENAME_LENGTH
	char fileLump[FILENAME_LENGTH];
	memset(fileLump, 0, FILENAME_LENGTH);
	strncpy(fileLump, filename, sizeof(fileLump));

	int numWritten = fwrite(fileLump, 1, FILENAME_LENGTH, output);
	if(numWritten != FILENAME_LENGTH) {
		perror("writeRecord");
		return -1;
	}

	numWritten = fwrite(hash, 1, HASH_LENGTH, output);
	if(numWritten != HASH_LENGTH) {
		perror("writeRecord");
		return -1;
	}

	numWritten = fwrite(key, 1, KEY_LENGTH, output);
	if(numWritten != KEY_LENGTH) {
		perror("writeRecord");
		return -1;
	}

	numWritten = fwrite(iv, 1, KEY_LENGTH, output);
	if(numWritten != KEY_LENGTH) {
		perror("writeRecord");
		return -1;
	}
	
	return 0;
}

FILERECORD *readRecord(FILE *input) {
	static FILERECORD record;
	int numRead = fread(record.filename, 1, FILENAME_LENGTH, input);
	if(numRead != FILENAME_LENGTH) {
		return NULL;
	}

	numRead = fread(record.hash, 1, HASH_LENGTH, input);
	if(numRead != HASH_LENGTH) {
		perror("readRecord");
		return NULL;
	}

	numRead = fread(record.key, 1, KEY_LENGTH, input);
	if(numRead != KEY_LENGTH) {
		perror("readRecord");
		return NULL;
	}

	numRead = fread(record.iv, 1, KEY_LENGTH, input);
	if(numRead != KEY_LENGTH) {
		perror("readRecord");
		return NULL;
	}

	return &record;
}

int addRecord(char *filename, unsigned char *hash, unsigned char *key, unsigned char *iv) {
	FILE *db = fopen(dbFilename, "rb+");
	if(db == NULL) {
		perror("addRecord");
		return -1;
	}

	//see if a record for this file already exits and overwrite it
	while(1) {
		long recordStart = ftell(db);
		if(recordStart < 0) {
			perror("ftell failed");
			return -1;
		}
		FILERECORD *record = readRecord(db);
		if(record == NULL) break;

		if(strcmp(record->filename, filename) == 0) {
			//jump back to start of record and overwrite
			if(fseek(db, recordStart, SEEK_SET) < 0) {
				perror("fseek failed");
				fclose(db);
				return -1;
			}

			//overwrite and exit
			int status = writeRecord(db, filename, hash, key, iv);
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

	int status = writeRecord(db, filename, hash, key, iv);
	fclose(db);
	if(status < 0) return status;
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

			//grab the last record in the file
			fseek(db, -RECORD_LENGTH, SEEK_END);
			//we will cut this last record off the file 
			long cutoff = ftell(db);
			FILERECORD *lastRecord = readRecord(db);
			if(lastRecord == NULL)  {
				fclose(db);
				return -1;
			}

			//write it over the target record
			fseek(db, targetPosition, SEEK_SET);
			writeRecord(db, lastRecord->filename, lastRecord->hash, lastRecord->key, lastRecord->iv);
			fclose(db);

			//remove the (now duplicated) last record from the end of the file
			if(truncate(dbFilename, cutoff) == -1) {
				perror("removeRecord()");
				return -1;
			}
			return 0;
		}
	}

	//wasn't in file anyway
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
	for(int i=0; i<HASH_LENGTH; ++i) putchar(hash[i]);
}

int printDatabase(char *filename) {
	FILE *database = fopen(filename, "rb");
	if(database == NULL) {
		perror("printDatabase()");
		return -1;
	}

	FILERECORD *record;
	while((record = readRecord(database)) != NULL) {
		printf("%s ", record->filename);	
		printHash(record->hash);
		printf("\n");
	}

	fclose(database);
	return 0;
}



/*
int main(int argc, char **argv) {
	char *filename = "test.txt";
	unsigned char *hash = (unsigned char *)"12948AF6374D4321";
	unsigned char *key = randomBytes(KEY_LENGTH);
	unsigned char *iv = randomBytes(KEY_LENGTH);

	addRecord(filename, hash, key, iv);

	addRecord("a", hash, key, iv);
	addRecord("b", hash, key, iv);
	addRecord("c", hash, key, iv);
	addRecord("d", hash, key, iv);
	addRecord("e", hash, key, iv);
	addRecord("f", hash, key, iv);

	printDatabase(dbFilename);
	removeRecord("a");
	printDatabase(dbFilename);
	removeRecord("d");
	printDatabase(dbFilename);
	removeRecord("c");
	printDatabase(dbFilename);
	removeRecord("b");

	printDatabase(dbFilename);


	free(key);
	free(iv);
}
*/
