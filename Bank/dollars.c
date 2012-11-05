#include <stdio.h>
#include <string.h>
#include "../netbase/netbase.h"
#include "dollars.h"

#define DOLLAR_FIRST_LINE "This is a certified cloud cheque issued by CLOUD BANK.\n"

/* Build a cloud dollar.  The first NOTE_SIZE contains the data
 * of the note itself, plus some random bytes to fill up the rest.
 * The last SIG_SIZE bytes are a signature of the first part. */
unsigned char *buildCloudDollar(int serial, int amount, int userid, EVP_PKEY *privateKey) {
	unsigned char *cloudDollar = randomBytes(CLOUD_DOLLAR_SIZE);
	if(cloudDollar == NULL) return NULL;

	//write the first part of the note
	snprintf((char *)cloudDollar, NOTE_SIZE, "%sSerial: %010d\nAmount: %010d\nUser: %010d\n", DOLLAR_FIRST_LINE, serial, amount, userid);

	unsigned int sigLength;
	//sign the note part of the cloud dollar
	unsigned char *signature = signData(cloudDollar, NOTE_SIZE, privateKey, &sigLength);
	if(sigLength != SIG_SIZE) {
		fprintf(stderr, "Warning: Signature in buildCloudDollar() was not expected size.\n");
		fprintf(stderr, "Was %d bytes\n", sigLength);
	}
	memcpy(cloudDollar + NOTE_SIZE, signature, SIG_SIZE);	

	return cloudDollar;
}

int verifyCloudDollar(char *cloudDollarFile, EVP_PKEY *publicKey) {
	//load the file into a buffer
	int fileSize = -1;
	unsigned char *cloudDollar = loadFile(cloudDollarFile, &fileSize);

	//make sure the first line matches
	if(strncmp((char *)cloudDollar, DOLLAR_FIRST_LINE, strlen(DOLLAR_FIRST_LINE)) != 0) return -1;

	int verified = verifyData(cloudDollar, NOTE_SIZE, cloudDollar + NOTE_SIZE, SIG_SIZE, publicKey);
	if(!verified) return -2;

	return 0;
}

int getDollarData(char *cloudDollar, int *serial, int *amount, int *user) {
	FILE *dollar = fopen(cloudDollar, "r");
	if(dollar == NULL) {
		perror("verifyCloudDollar()");
		return -1;
	}

	char buffer[1024];
	//read first line
	fgets(buffer, sizeof(buffer), dollar);
	int numMatched = fscanf(dollar, "Serial: %010d\nAmount: %010d\nUser: %010d", serial, amount, user);
	if(numMatched != 3) {
		perror("getSerial()");
		fclose(dollar);
		return -1;
	}

	fclose(dollar);

	return 0;
}
