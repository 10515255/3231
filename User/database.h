#include <openssl/md5.h>

#define KEY_LENGTH 32
#define HASH_LENGTH MD5_DIGEST_LENGTH 
#define FILENAME_LENGTH 512

typedef struct {
	char filename[FILENAME_LENGTH];
	unsigned char hash[HASH_LENGTH];
	unsigned char key[KEY_LENGTH];
	unsigned char iv[KEY_LENGTH];
} FILERECORD;

/* Add a record of the given file to the database.  If it already exits in the databse
 * it's information will be updated */
int addRecord(char *filename, unsigned char *hash, unsigned char *key, unsigned char *iv);

/* Get a pointer to the record in the database with the given filename */
FILERECORD *getRecord(char *targetFilename);
