#define NOTE_SIZE 128
#define SIG_SIZE 256 
#define CLOUD_DOLLAR_SIZE (NOTE_SIZE + SIG_SIZE)

unsigned char *buildCloudDollar(int serial, int amount, int userid, EVP_PKEY *privateKey);
int verifyCloudDollar(char *cloudDollarFile, EVP_PKEY *publicKey);
int getDollarData(char *cloudDollar, int *serial, int *amount, int *user);
