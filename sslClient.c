#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


int openConnection(char *hostname, char *port) {

	char *hostString = malloc(strlen(hostname) + strlen(port) + 2);
	if(hostString == NULL) return -1;
	sprintf(hostString, "%s:%s", hostname, port);
	//attempt to establish a new connection 
	//and ensure success
	BIO *bio = BIO_new_connect(hostString);
	if(bio == NULL) {
		fprintf(stderr, "Failed to open connection.\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//this must be called to verify a succesfull connection
	//has been established
	if(BIO_do_connect(bio) <= 0) {
		fprintf(stderr, "Failed to verify successful connection?\n");
		unsigned long err = ERR_get_error();
		fprintf(stderr, "Err: %lu\n", err); 
		fprintf(stderr, "%s\n", ERR_error_string(err, NULL));
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//then just read and write with BIO_read(bio, buffer, length)
	//and BIO_write(bio.buffer, length)
	char *msg = "HELLO";
	BIO_write(bio, msg, strlen(msg));

	BIO_free(bio);
	
	return 0;
}




int main(int argc, char **argv) {
	if(argc < 3) {
		fprintf(stderr, "Expected a hostname and port.\n");
		exit(EXIT_FAILURE);
	}

	char *hostname = argv[1];
	char *port = argv[2];

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	openConnection(hostname, port);
}
