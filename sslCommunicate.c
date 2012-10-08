#include "sslCommunicate.h"

/* OpenSSL headers */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

/* Make repeated calls to BIO_write until our entire
message has been sent. */
int sendAll(BIO *conn, char *buffer, int length) {
	int numLeft = length;
	int totalSent = 0;	

	while(numLeft > 0) {
		char *offset = buffer + numSent;
		int numSent = BIO_write(conn, offset, numLeft);
		if(numSent < 1) {
			return numSent;
		}

		totalSent += numSent;
		numLeft -= numSent;
	}

	return totalSent;
}

/* Make repeated calls to BIO_read until our entire
message has been read. */
int readAll(BIO *conn, char *buffer, int length) {
	int numLeft = length;
	int totalRead = 0;

	while(numLeft > 0) {
		char *offset = buffer + numRead;
		int numRead = BIO_read(conn, offset, numLeft);
		if(numRead < 1) {
			return numRead;
		}

		totalRead += numRead;
		numLeft -= numRead;
	}

	return totalRead;
}
