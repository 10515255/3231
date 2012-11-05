#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"
#include "database.h"
#include "../Cloud/cloudProtocol.h"

#include "../Bank/bankServer.h"

#define MAX_COMMAND_SIZE 512 

#define TRUST_STORE "Certs/trustStore.pem"
#define BANK_PUBLIC_KEY "Certs/bankPublicKey.pem"


int userid;
EVP_PKEY *bankPublicKey;

void stripNewline(char *string) {
	string[strlen(string)-1] = '\0';
}

int clientGetBalance(BIO *conn)  {
    if ( writeInt( conn, GET_BALANCE_CODE ) == -1 ) return -1;
    
    int balance = readInt(conn);
    
    return balance;
}

int clientWithdraw(BIO *conn, int amount, char *outFilename)  {
	//start the server's side of the protocol
	if ( writeInt( conn, WITHDRAW_CODE ) == -1 ) return -1;
	
	// send how much we want to withdraw
	int status = writeInt(conn, amount);
	if ( status == -1 ) return -1;
	
	// get response
	status = readInt(conn);
	if(status == -2) {
		printf("Insufficient funds. Type \"balance\" to get your balance.");
		return -1;
	}
	if ( status != 0 ) return -1;
	
	//read the cloud cheque in as a packet of data
	unsigned char buffer[CLOUD_DOLLAR_SIZE];
	status = readPacket(conn, buffer, sizeof(buffer) );
	if ( status == -1 ) return -1;

	//verify it is a true bank cloud cheque
	int verified = verifyData(buffer, NOTE_SIZE, buffer+NOTE_SIZE, SIG_SIZE, bankPublicKey);
	
	//save the cheque to file
	status = writeDataToFile(outFilename, buffer, sizeof(buffer) );
	if ( status == -1 ) return -1;

	if(!verified) {
		printf("Warning: Cloud dollar was not signed by the the cloud bank.\n");
	}

	return 0;
}

int handleServer(BIO *server) {
	//tell the bank who we are
	if(writeInt(server, userid) == -1) return -1;

	printf("Connected to the CLOUD BANK.\n");
	printf("Commands:\n");
	printf("\tbalance\n");
	printf("\twithdraw amount outfilename\n");
	printf("\tquit\n");

	char buffer[MAX_COMMAND_SIZE];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		stripNewline(buffer);

		
		if ( strncmp(buffer, "balance", 7) == 0 )  {
			int status = clientGetBalance(server);
			printf("%d\n", status);
		}
		else if ( strncmp(buffer, "withdraw ", 9) == 0 )  {
			int amount;
			char outFilename[512];
			int numMatched = sscanf(buffer+9, "%d %s", &amount, outFilename);
			if ( numMatched != 2 || amount < 1)   {
			    printf("Usage: withdraw amount outfilename");
			}
			else  {
			      int status = clientWithdraw(server, amount, outFilename);
				  if(status == -1) printf("Failed to withdraw.\n");
				  else printf("%d dollars saved in %s\n", amount, outFilename);
			}
		}    
		else if ( strcmp(buffer, "quit") == 0) {
			break;
		}
		else {
			printf("Invalid Command\n");
			writeInt(server, 0);
			continue;
		}
	}

	return 0;
}


int main(int argc, char **argv) {
	if(argc < 6) {
		fprintf(stderr, "Expected a hostname, port, certificate, privatekey and userid.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];
	char *certFile = argv[3];
	char *privKeyFile = argv[4];
	//set the global userid
	userid = atoi(argv[5]);
	//load the banks public key
	bankPublicKey = loadPublicKey(BANK_PUBLIC_KEY);
	if(bankPublicKey == NULL) {
		fprintf(stderr, "Failed to load the bank's public key: %s\n");
		exit(EXIT_FAILURE);
	}

	//connect to the server, then run handleServer() on the resulting connection
	initOpenSSL();
	int status = connectToServer(hostname, port, certFile, privKeyFile, TRUST_STORE, &handleServer);

	return status;
}
