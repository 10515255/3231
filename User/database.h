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
