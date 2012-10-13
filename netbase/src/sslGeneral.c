/* OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For our simple packet structure */
#include <stdint.h>
#include <arpa/inet.h>

#include "sslGeneral.h"

/* Make repeated calls to BIO_write until our entire
message has been sent. */
int sendAll(BIO *conn, char *buffer, int length) {
	int numLeft = length;
	int totalSent = 0;	

	while(numLeft > 0) {
		char *offset = buffer + totalSent;
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
		char *offset = buffer + totalRead;
		int numRead = BIO_read(conn, offset, numLeft);
		if(numRead < 1) {
			return numRead;
		}

		totalRead += numRead;
		numLeft -= numRead;
	}

	return totalRead;
}

/* Write the buffer contents over the network, using a simpl
 * packet structure.  The first 4 bytes are a header indicating
 * how many bytes to follow (in the body). */
int writePacket(BIO *conn, char *buffer, int length) {
	//send the header (4 byte int in network byte order)
	uint32_t numBytes = htonl(length);
	int status = sendAll(conn, (char *)&numBytes, sizeof(uint32_t));
	if(status < 1) return status;	

	//send the body (contents of buffer)
	status = sendAll(conn, buffer, length);
	if(status < 1) return status;
	
	return length;
}

/* Read a simple packet structure as it arrives over the 
 * network.  It returns the length of the body, which is the
 * number of bytes which it copies into the give buffer. */
int readPacket(BIO *conn, char *buffer, int maxLength) {
	//read the packet header
	uint32_t numBytes;
	int status = readAll(conn, (char *)&numBytes, sizeof(uint32_t));
	if(status < 1) return status;

	int packetLength = ntohl(numBytes);
	//ensure buffer has capacity
	if(packetLength > maxLength) return -2;

	//read the packet body
	status = readAll(conn, buffer, packetLength);
	if(status < 1) return status;

	return packetLength;
}

//used for BIO_new_connect
//user for BIO_new_accept
/* Join a hostname string and a port string into the format expected
 * by the openssl calls BIO_new_connect and BIO_new_accept.
 *
 * i.e "hostname:port"
 */
char *buildHostString(char *hostname, char *port) {
	//if hostname is not specified set it to localhost? 
	if(hostname == NULL) hostname = "127.0.0.1";

	//both strings plus a : seperator and a terminal
	int numChars = strlen(hostname) + strlen(port) + 2;
	char *hostString = malloc(numChars * sizeof(char));
	if(hostString == NULL) {
		fprintf(stderr, "malloc() failed in buildHostString()\n");
		exit(EXIT_FAILURE);
	}
	snprintf(hostString, numChars, "%s:%s", hostname, port);

	return hostString;
}

/* Initialise OpenSSL for use */
void initOpenSSL() {
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	return;
}
