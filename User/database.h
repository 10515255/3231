#include <openssl/md5.h>

#define FILENAME_LENGTH 512
/* Store a number of random salts, and the corresponding hashes
 * for this file's contents preceded by the salt */
#define HASH_LENGTH MD5_DIGEST_LENGTH 
#define SALT_LENGTH HASH_LENGTH
#define NUM_HASHES 4
/* Use one byte to indicate the number of hashes we have "consumed" */
#define HASH_INDEX_LENGTH 1

#define KEY_LENGTH 32
#define IV_LENGTH 32

/* Calculate some offsets to make accessing record data easier */
#define FILENAME_OFFSET	0
#define HASH_INDEX_OFFSET (FILENAME_OFFSET + FILENAME_LENGTH)
#define HASH_OFFSET		(HASH_INDEX_OFFSET + HASH_INDEX_LENGTH)
#define KEY_OFFSET		(HASH_OFFSET + NUM_HASHES*(HASH_LENGTH+ SALT_LENGTH))
#define IV_OFFSET		(KEY_OFFSET + KEY_LENGTH)
#define RECORD_LENGTH	(IV_OFFSET + IV_LENGTH)


/* A structure to read our records into, and write them out of */
typedef struct {
	char filename[FILENAME_LENGTH];
	unsigned char hashIndex[HASH_INDEX_LENGTH];
	unsigned char hashData[NUM_HASHES][HASH_LENGTH + SALT_LENGTH];
	unsigned char key[KEY_LENGTH];
	unsigned char iv[KEY_LENGTH];
} FILERECORD;

/* Add a record of the given file to the database.  If it already exits in the databse
 * it's information will be updated */
int addRecord(char *filename, unsigned char hashIndex,  unsigned char **hashes, unsigned char **salts, unsigned char *key, unsigned char *iv);

/* Get a pointer to the record in the database with the given filename */
FILERECORD *getRecord(char *targetFilename);

int removeRecord(char *targetFilename);
