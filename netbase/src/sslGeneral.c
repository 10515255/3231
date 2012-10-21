#define _POSIX_SOURCE

#include <stdio.h>

/* OpenSSL headers */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* For our simple packet structure */
#include <stdint.h>
#include <arpa/inet.h>

/* To determine size of a file before reading. */
#include <sys/stat.h>
#include <sys/types.h>

#include "sslGeneral.h"

//reasonable?
#define MAX_FILENAME_LENGTH 64 
#define MAX_FILE_SIZE (1024*1024)

/* Make repeated calls to BIO_write until our entire
message has been sent. */
int sendAll(BIO *conn, char *buffer, int length) {
	int numLeft = length;
	int totalSent = 0;	

	while(numLeft > 0) {
		char *offset = buffer + totalSent;
		int numSent = BIO_write(conn, offset, numLeft);
		if(numSent < 1) return numSent;

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
		if(numRead < 1) return numRead;

		totalRead += numRead;
		numLeft -= numRead;
	}

	return totalRead;
}

/* Write the buffer contents over the network, using a simple
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
	if(packetLength > maxLength) {
		fprintf(stderr, "readPacket() received a packet longer than the allocated space.\n");
		return -2;
	}

	//read the packet body
	status = readAll(conn, buffer, packetLength);
	if(status < 1) return status;

	return packetLength;
}

/* Send a null-terminated string in a simple packet. */
int writeString(BIO *conn, char *string) {
	//include the terminal character in our packet
	return writePacket(conn, string, strlen(string)+1);
}

/* Read a null-terminated string from a simple packet */
int readString(BIO *conn, char *buffer, int maxLength) {
	return readPacket(conn, buffer, maxLength);
}

/* Send a file across the network. The filename argument
 * will be sent to indicate to the other side what it should
 * be saved as. */
int sendFile(BIO *conn, FILE *file, char *filename) {
	if(file == NULL || filename == NULL) return -1;

	//determine the length of the file
	struct stat fileDetails;
	int fd = fileno(file);
	if(fd < 0) {
		perror("fileno() in sendFile():");
		return -1;
	}
	int success = fstat(fd, &fileDetails);
	if(success < 0) {
		perror("sendFile(): ");
		return -1;
	}	

	uint32_t fileSize = fileDetails.st_size;
	//convert to network byte order
	uint32_t netSize = htonl(fileSize);

	/* Send a header message with the filename, and length */

	//send the filename first in a simple packet
	int status = writePacket(conn, filename, strlen(filename));
	if(status < 1) return status;

	//send the file length
	status = sendAll(conn, (char *)&netSize, sizeof(uint32_t));
	if(status < 1) return status;	
	/* Now transfer the file */
	rewind(file);
	char fileBuffer[BUFSIZ];

	while(1) {
		//read a chunk
		int numRead = fread(fileBuffer, 1, BUFSIZ, file); 
		if(numRead == 0) break;

		//send that chunk over the network
		int status = sendAll(conn, fileBuffer, numRead);
		if(status < 1) return status;

		fileSize -= numRead;
	}

	printf("File transfer over\n");

	if(fileSize != 0) {
		fprintf(stderr, "sendFile(): fileSize non-zero after sending. Incomplete??\n");
		return -1;
	}

	return 1;
}

/* Receive a file over the network, as sent by sendFile() above. */
int recvFile(BIO *conn) {
	//the filename will arrive in a simple packet
	char filename[MAX_FILENAME_LENGTH];
	int status = readPacket(conn, filename, sizeof(filename));
	if(status < 1) return status;
	//null terminate the filename, so we can use it from this array
	filename[status] = '\0';
	printf("Got the filename, %s\n", filename);
	
	//read the file length
	uint32_t numBytes = 0;
	status = readAll(conn, (char *)&numBytes, sizeof(uint32_t));
	if(status < 1) {
		fprintf(stderr, "readAll() return %d in recvFile()\n", status);
		return status;
	}
	numBytes = ntohl(numBytes);
	printf("The file will have %u bytes.\n", numBytes);

	/* Here we will eventually check to make sure the client has sufficient
	paid storage for the incoming file.  They will probably wait for us to tell
	themn whether to send the file or not */
	if(numBytes > MAX_FILE_SIZE) {
		fprintf(stderr, "That file is too big.\n");
		return -1;
	}

	//open the file for writing
	FILE *ofp = fopen(filename, "wb");
	if(ofp == NULL) {
		perror("fopen() in recvFile():");
		return -1;
	}

	//read the file, and write to disk
	char fileBuffer[BUFSIZ];
	printf("The file will have %u bytes.\n", numBytes);
	uint32_t bytesLeft = numBytes;
	printf("The file will have %u bytes.\n", bytesLeft);
	while(numBytes > 0) {
		//read until a full buffer (unless remaining bytes would not fill it)
		int amount = (numBytes < sizeof(fileBuffer)) ? numBytes : sizeof(fileBuffer);
		printf("I'll attempt to read %d bytes\n", amount);
		int status = readAll(conn, fileBuffer, amount);
		if(status < 1) {
			fclose(ofp);
			return -1;
		}

		//write this much to disk
		int numWritten = fwrite(fileBuffer, 1, amount, ofp);
		if(numWritten != amount) {
			perror("fwrite() in recvFile()");
			fclose(ofp);
			return -1;
		}
		printf("I read %d bytes\n", numWritten);

		numBytes -= amount;
	}

	printf("Finished receiving file.\n");
	fclose(ofp);

	return 1;
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

/* Initialise OpenSSL for use */
void initOpenSSL() {
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	return;
}
