#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../netbase/netbase.h"
#include "database.h"
#include "../Cloud/cloudProtocol.h"

#include "../Bank/bankServer.h"

#define MAX_COMMAND_SIZE 512 

#define TRUST_STORE "Certs/trustStore.pem"


int userid;

void stripNewline(char *string) {
	string[strlen(string)-1] = '\0';
}



int clientGetBalance(BIO *conn)  {
    if ( writeInt( conn, GET_BALANCE_CODE ) == -1 ) return -1;
    
    int balance = readInt(conn);
    
    return balance;
}

int clientWithdraw(BIO *conn, int amount)  {
	if ( writeInt( conn, WITHDRAW_CODE ) == -1 ) return -1;
	
	// send how much we want to withdraw
	int status = writeInt(conn, amount);
	
	if ( status == -1 ) return -1;
	unsigned char buffer[CLOUD_DOLLAR_SIZE];
	
	// get response
	status = readInt(conn);
	if ( status != 0 ) return -1;
	
	status = readPacket(conn, buffer, sizeof(buffer) );
	if ( status == -1 ) return -1;
	status = writeDataToFile( "cheque", buffer, sizeof(buffer) );
	if ( status == -1 ) return -1;
	return 0;
	
	
}

int handleServer(BIO *server) {
	if(writeInt(server, userid) == -1) return -1;

	char buffer[MAX_COMMAND_SIZE];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		stripNewline(buffer);

		
		if ( strncmp(buffer, "balance", 7) == 0 )  {
			int status = clientGetBalance(server);
			printf("%d\n", status);
		}
		else if ( strncmp(buffer, "withdraw ", 9) == 0 )  {
			int amount;
			int numMatched = sscanf(buffer+9, "%d", &amount);
			if ( numMatched != 1 || amount < 1)   {
			    printf("Not a valid amount to withdraw\n");
			}
			else  {
			      int status = clientWithdraw(server, amount);
			      printf("status is : %d\n", status);
			}
		}    
		else {
			printf("Invalid Command\n");
			writeInt(server, 0);
			continue;
		}

		/*
		int status = readString(server, buffer, sizeof(buffer));
		if(status < 1) {
			printf("Error by readString() in handleServer()\n");
			return -1;
		}
		*/
	}

	return 0;
}


int main(int argc, char **argv) {
	if(argc < 6) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];
	char *certFile = argv[3];
	char *privKeyFile = argv[4];
	//set the global userid
	userid = atoi(argv[5]);

	//connect to the server, then run handleServer() on the resulting connection
	initOpenSSL();
	int status = connectToServer(hostname, port, certFile, privKeyFile, TRUST_STORE, &handleServer);

	return status;
}
