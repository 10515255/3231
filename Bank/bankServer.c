#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "../netbase/netbase.h"
#include "bankServer.h"
#include "dollars.h"
#include "database.h"

#define MAX_FILE_SIZE 1024
#define BUFFER_SIZE 1024

#define TRUST_STORE "Certs/trustStore.pem"
#define SERVER_CERTIFICATE "Certs/bankCert.pem"
#define SERVER_PRIVKEY "Certs/bankPrivateKey.pem"
#define SERVER_PUBKEY "Certs/bankPublicKey.pem"

EVP_PKEY *privateKey;
EVP_PKEY *publicKey;
int serialNumber = 0;

int loadKeys() {
	privateKey = loadPrivateKey(SERVER_PRIVKEY);	
	publicKey = loadPublicKey(SERVER_PUBKEY);

	if(privateKey == NULL || publicKey == NULL) return -1;
	return 0;
}

int serverGetBalance(BIO *conn, int userid)  {
	int balance = getBalance(userid);

	if ( writeInt(conn, balance) == -1 ) return -1;
	if(balance == -1) return -1;
	return 0;
}

int serverWithdraw(BIO *conn, int userid)  {
	//read the amount the user wants to withdraw
	int amount = readInt(conn);
	int status = 0;
	if ( amount < 0 ) status = -1;

	int balance = getBalance(userid);
	if(balance == -1) status = -1;
	//check for insufficient funds
	if ( balance < amount ) status = -2;

	//send error code to indicate withdrawal not going ahead
	if ( status < 0 )  {
		writeInt(conn, status);
		return -1;
	}
	//send 0 to indicate withdrawal going ahead
	if (  writeInt(conn, 0) == -1 ) return -1;

	//update the users balance, and build a cloud cheque for the amount
	updateBalance(userid, balance - amount);
	unsigned char* cheque = buildCloudDollar( serialNumber, amount, userid, privateKey );
	serialNumber++;

	//send the cloud cheque to the user
	status = writePacket( conn, cheque, CLOUD_DOLLAR_SIZE );
	free(cheque);
	if ( status < 0 )  {
		return -1;
	}

	return 0;
}

int serverCashCheque(BIO *conn, int userid) {
}

int handleClient(BIO *client) {	
	//find out who the user is
	int userid = readInt(client);
	if(userid == -1) return -1;
	printf("User %d has connected.\n", userid);

	/* Accept commands codes from the client program to determine which 
	 * functionality of the protocol is being initiate. */
	while(1) {
		int commandCode = readInt(client);
		if(commandCode == -1) {
			printf("User %d disconnected.\n");
			return -1;
		}
		int status = 0;

		switch (commandCode)  {
			case GET_BALANCE_CODE:
				printf("User %d requested a balance.\n");
				status = serverGetBalance(client, userid);
				if(status == -1) printf("serverGetBalance() failed.\n");
				else printf("Success.\n");
				break;
			case WITHDRAW_CODE:
				printf("User %d wants to withdraw money.\n");
				status = serverWithdraw(client, userid);
				if(status == -1) printf("serverWithdraw() failed.\n");
				else printf("Success\n");
				break;
			case CASH_CHEQUE_CODE:
				printf("User %d want to cash a cheque.\n");
				status = serverCashCheque(client, userid);
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
