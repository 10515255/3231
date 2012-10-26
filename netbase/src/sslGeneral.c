/* Some useful general functions. */
#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/stat.h>
#include <unistd.h>

#include "sslGeneral.h"

/* Initialise OpenSSL for use */
void initOpenSSL() {
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	return;
}

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

int sizeOfFile(char *filename) {
	//determine the file size
	struct stat s;
	int status = stat(filename, &s);
	if(status == -1) {
		perror("loadFile");
		return -1;
	}

	return s.st_size;
}
