#include <stdio.h>

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include "sslGeneral.h"
#include "sslClient.h"

/* Connect to a server at the given hostname on the given port.
 * Once a connection is established it passes the connection to
 * the argument serverHandler() function, which undertakes the
 * actual interaction with the server. */
int connectToServer(char *hostname, char *port, char *certFile, char *privKeyFile, char *trustStore, int (*serverHandler)(BIO *) ) {
	//for some bug
	SSL_library_init();

	//prepare the SSL context for a secure connection
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
	if(ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//load the trust certificate store
	int status = SSL_CTX_load_verify_locations(ctx, trustStore, NULL); 
	if(status == 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//load the client's certificate and private key
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

	//establish a BIO to handle the connection
	BIO *bio = BIO_new_ssl_connect(ctx);
	SSL *ssl;
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	char *hostString = buildHostString(hostname, port);
	BIO_set_conn_hostname(bio, hostString);

	//verify the connection succeeded and do handshake
	if(BIO_do_connect(bio) <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	//ensure certificate is valid
	long valid = SSL_get_verify_result(ssl);
	if(valid != X509_V_OK) {
		fprintf(stderr, "Warning: Failed to verify certificate of the server.\n");
		return -1;
	}

	//hand off the connection to the given handler function
	status = serverHandler(bio);

	//we are done with this connection, free any resources we allocated
	BIO_free_all(bio);
	SSL_CTX_free(ctx);
	free(hostString);

	return status;
}
