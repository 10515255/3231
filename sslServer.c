#include <stdio.h>
#include <stdlib.h>

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


int startServer() {

	//BIO *bio; //not needed for unencrypted connection??
	BIO *abio;
	BIO *out;

	//combines BIO_new() and BIO_set_accept_port()
	abio = BIO_new_accept("7777");
	//this one actually tries to bind the port and whatnot
	if(BIO_do_accept(abio) <= 0) {
		fprintf(stderr, "Failed to intialise accept BIO.\n");
		//prints the messages for all errors in the error queue
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//wait for incoming connections
	while(1) {

		printf("Listening for incoming connection:\n");

		if(BIO_do_accept(abio) <= 0) {
			fprintf(stderr, "Failed to catch incoming connection?\n");
			continue;
		}

		//grab the BIO * for this incoming connection
		out = BIO_pop(abio);

		//do the handshake?? needed if unencrypted?
		/*
		if(BIO_do_handshake(out) <= 0) {
			fprintf(stderr, "Failed to handshake with incoming connection.\n");
			unsigned long err = ERR_peek_last_error();
			fprintf(stderr, "%s\n", ERR_error_string(err, NULL));
			continue;
		}
		*/

		printf("We got a connection!\n");

		char buffer[1024];
		int numRead = BIO_read(abio, buffer, sizeof(buffer));
		buffer[numRead] = '\0';
		printf("They say: %s\n", buffer);

		//we must free this once we are done?
		BIO_free(out);
	}

	BIO_free(abio);

	return 0;
}




int main(int argc, char **argv) {

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();

	startServer();

	exit(EXIT_SUCCESS);

}
