#include <stdio.h>
#include <stdlib.h>

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "sslGeneral.h"
#include "sslServer.h"

/* Start a server, listening for incoming connections.
 * Does not yet use any encryption / SSL / whatever. */
int runServer(char *hostname, char *port, char *certFile, char *privKeyFile, char *trustStore, int (*clientHandler)(BIO *)) {

	//for some bug
	SSL_library_init();

	//prepare for a secure connection
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
	if(ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//load the certificates of users we trust
	int status = SSL_CTX_load_verify_locations(ctx, trustStore, NULL);
	
	//load the servers certificate and private key
	status = SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM);
	if(status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	status = SSL_CTX_use_RSAPrivateKey_file(ctx, privKeyFile, SSL_FILETYPE_PEM);
	if(status != 1) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//require clients to authenticate themselves with a certificate
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	//setup the BIO structure for this connection
	BIO *bio = BIO_new_ssl(ctx, 0);
	if(bio == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	SSL ssl;
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(&ssl, SSL_MODE_AUTO_RETRY);

	char *hostString = buildHostString(hostname, port); 
	BIO *acceptor = BIO_new_accept(hostString);
	BIO_set_bind_mode(acceptor, BIO_BIND_REUSEADDR);
	BIO_set_accept_bios(acceptor, bio);

	//bind and start listening
	if(BIO_do_accept(acceptor) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	while(1) {
		printf("\nListening on %s\n", hostString);

		//accept client connections as they arrive
		if(BIO_do_accept(acceptor) <= 0) {
			fprintf(stderr, "Failed to catch incoming connection?\n");
			continue;
		}
		printf("A client connected!\n");

		//grab the connection and perform ssl handshake
		BIO *client = BIO_pop(acceptor);
		int status = BIO_do_handshake(client);
		if(status <= 0) {
			fprintf(stderr, "Handshake failed.\n");
			ERR_print_errors_fp(stderr);
			BIO_free(client);
			continue;
		}

		//handle the connection
		clientHandler(client);
		BIO_free(client);
	}

	//we have finished running the server, free any resources we allocated
	BIO_free_all(acceptor);
	free(hostString);

	return 0;
}
