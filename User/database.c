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
			int status = fseek(db, recordStart, SEEK_SET);
			if(status < 0) {
				perror("fseek failed");
				fclose(db);
				return -1;
			}

			//write and exit
			status = writeRecord(db, filename, hash, key, iv);
			fclose(db);
			if(status < 0) return status;
			return 0;
		}
	}
	
	fclose(db);

	db = fopen(dbFilename, "ab");
	if(db == NULL) {
		perror("fopen failed");
		return -1;
	}

	//if not found, add it on the end
	int status = writeRecord(db, filename, hash, key, iv);
	fclose(db);
	if(status < 0) return status;
	
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


/*
int main(int argc, char **argv) {
	char *filename = "test.txt";
	char *hash = "12948AF6374D4321";
	char *key = randomBytes(KEY_LENGTH);
	char *iv = randomBytes(KEY_LENGTH);

	addRecord(filename, hash, key, iv);

	filename = "other.txt";
	hash = "1111111111111111";
	addRecord(filename, hash, key, iv);

	FILERECORD *r = getRecord("other.txt");
	printf("%s\n", r->filename);
	for(int i=0; i<HASH_LENGTH; ++i) putchar(r->hash[i]);
	putchar('\n');

	hash = "2222222222222222";
	addRecord(filename, hash, key, iv);

	r = getRecord("other.txt");

	printf("%s\n", r->filename);
	for(int i=0; i<HASH_LENGTH; ++i) putchar(r->hash[i]);
	putchar('\n');


	free(key);
	free(iv);
}
*/
