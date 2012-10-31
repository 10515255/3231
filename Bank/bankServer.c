#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "../netbase/netbase.h"
#include "bankServer.h"
#include "database.h"

#define MAX_FILE_SIZE 1024
#define BUFFER_SIZE 1024

#define NOTE_SIZE 128
#define SIG_SIZE 256 
#define CLOUD_DOLLAR_SIZE (NOTE_SIZE + SIG_SIZE)

#define TRUST_STORE "Certs/1Cert.pem"
#define SERVER_CERTIFICATE "Certs/cloudCert.pem"
#define SERVER_PRIVKEY "Certs/cloudPrivateKey.pem"
#define SERVER_PUBKEY "Certs/cloudPublicKey.pem"



EVP_PKEY *privateKey;
EVP_PKEY *publicKey;
int userid;
int serialNumber = 0;

int loadKeys() {
	privateKey = loadPrivateKey(SERVER_PRIVKEY);	
	publicKey = loadPublicKey(SERVER_PUBKEY);

	if(privateKey == NULL || publicKey == NULL) return -1;
	return 0;
}

/* Build a cloud dollar.  The first NOTE_SIZE contains the data
 * of the note itself, plus some random bytes to fill up the rest.
 * The last SIG_SIZE bytes are a signature of the first part. */
unsigned char *buildCloudDollar(int serial, int amount) {
	unsigned char *cloudDollar = randomBytes(CLOUD_DOLLAR_SIZE);
	if(cloudDollar == NULL) return NULL;

	//write the first part of the note
	snprintf(cloudDollar, NOTE_SIZE, "This is a certified cloud cheque issued by CLOUD BANK.\nSerial: %010d\nAmount: %010d\n", serial, amount); 

	int sigLength;
	//sign the note part of the cloud dollar
	char *signature = signData(cloudDollar, NOTE_SIZE, privateKey, &sigLength);
	if(sigLength != SIG_SIZE) {
		fprintf(stderr, "Warning: Signature in buildCloudDollar() was not expected size.\n");
		fprintf(stderr, "Was %d bytes\n", sigLength);
	}
	memcpy(cloudDollar + NOTE_SIZE, signature, SIG_SIZE);	

	return cloudDollar;
}

int verifyCloudDollar(char *cloudDollar) {
	int verified = verifyData(cloudDollar, NOTE_SIZE, cloudDollar + NOTE_SIZE, SIG_SIZE, publicKey);

	return verified;
}

int serverGetBalance(BIO *conn)  {
	int balance = getBalance(userid);
	
	if ( writeInt(conn, balance) == -1 ) return -1;
	return 0;
}

int serverWithdraw(BIO *conn)  {
	int amount = readInt(conn);
	int status;
	if ( amount < 0 ) status = -1;

	
	
	int balance = getBalance(userid);
	if ( balance < amount ) status = -1;

	if ( status < 0 )  {
	    writeInt(conn, status);
	    return -1;
	}

	
	if (  writeInt(conn, 0) == -1 ) return -1;
	updateBalance(userid, balance - amount);
	
	unsigned char* cheque = buildCloudDollar( serialNumber, amount );

	serialNumber++;

	status = writePacket( conn, cheque, CLOUD_DOLLAR_SIZE );
	free(cheque);
	if ( status < 0 )  {
	    return -1;
	}
	
	

	
	
	
}

int handleClient(BIO *client) {	
	//find out who the user is
	userid = readInt(client);
	if(userid == -1) return -1;
	printf("User %d has connected.\n", userid);

	/* Accept commands codes from the client program to determine which 
	 * functionality of the protocol is being initiate. */
	while(1) {
		int commandCode = readInt(client);
		if(commandCode == -1) return -1;
		printf("Client: %d\n", commandCode);

		switch (commandCode)  {
		  case GET_BALANCE_CODE:
		    serverGetBalance(client);
		    break;
		  case WITHDRAW_CODE:
		    serverWithdraw(client);
		    break;
		  default:
		    printf("Unrecognised command\n");
		    break;
		}
	}


	return 0;
}


int main(int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];

	loadKeys();
	initOpenSSL();
	int status = runServer(hostname, port, SERVER_CERTIFICATE, SERVER_PRIVKEY, TRUST_STORE, &handleClient);
	return status;

}
