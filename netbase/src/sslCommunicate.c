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
#include "sslCommunicate.h"

//reasonable?
#define MAX_FILENAME_LENGTH 64 
#define MAX_FILE_SIZE (1024*1024)

int readInt(BIO *conn) {
	uint32_t number = 0;
	int status = readAll(conn, (char *)&number, sizeof(uint32_t));
	if(status < 1) {
		return -1;
	}
	number = ntohl(number);
	return number;
}

int writeInt(BIO *conn, int n) {
	uint32_t number = htonl(n);
	int status = writeAll(conn, (char *)&number, sizeof(uint32_t));
	if(status < 1) return status;	

	return 1;
}

/* Make repeated calls to BIO_write until our entire
message has been sent. */
int writeAll(BIO *conn, char *buffer, int length) {
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
	int status = writeAll(conn, (char *)&numBytes, sizeof(uint32_t));
	if(status < 1) return status;	

	//send the body (contents of buffer)
	status = writeAll(conn, buffer, length);
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
int writeFile(BIO *conn, char *filename, char *writeName) {
	//if no alternate name supplied, just use it's actual name
	if(writeName == NULL) writeName = filename;

	FILE *ifp = fopen(filename, "rb");
	if(ifp == NULL) {
		perror("writeFile");
		//send NO_SUCH_FILE as the file length to indicate file is not coming
		writeInt(conn, NO_SUCH_FILE);
		return NO_SUCH_FILE;
	}

	//send the file length in 4 bytes
	int fileSize = sizeOfFile(filename);
	if(writeInt(conn, fileSize) == -1) return -1;
	if(fileSize == -1) return -1;
	
	//send the filename first in a simple packet
	if(writeString(conn, writeName) < 1) return -1;

	/* Now transfer the file */
	char fileBuffer[BUFSIZ];
	while(fileSize > 0) {
		//read a chunk
		int numRead = fread(fileBuffer, 1, BUFSIZ, ifp); 
		if(numRead == 0) break;

		//send that chunk over the network
		int status = writeAll(conn, fileBuffer, numRead);
		if(status < 1) return status;

		fileSize -= numRead;
	}

	if(fileSize != 0) {
		fprintf(stderr, "writeFile(): fileSize non-zero after sending. Incomplete??\n");
		return -1;
	}

	return 1;
}


/* Receive a file over the network, as sent by sendFile() above.
 * If a filename is provided, the file will be saved with this name,
 * otherwise it will be saved with the name sent preceding the packet.*/
int recvFile(BIO *conn, char *filename) {
	//receive the number of bytes in this file
	int numBytes = readInt(conn);
	if(numBytes == NO_SUCH_FILE) return NO_SUCH_FILE;
	if(numBytes == -1) return -1;

	//receive the server's name for this file
	char serverFilename[MAX_FILENAME_LENGTH];
	if(readString(conn, serverFilename, sizeof(serverFilename)) == -1) return -1;


	//if no filename was supplied, use the server's filename
	if(filename == NULL) filename = serverFilename;

	//open the file for writing
	FILE *ofp = fopen(filename, "wb");
	if(ofp == NULL) {
		perror("fopen() in recvFile():");
		return -1;
	}

	//read the file, and write to disk
	char fileBuffer[BUFSIZ];
	while(numBytes > 0) {
		//read until a full buffer (unless remaining bytes would not fill it)
		int amount = (numBytes < sizeof(fileBuffer)) ? numBytes : sizeof(fileBuffer);
		if(readAll(conn, fileBuffer, amount) < 1) {
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

		numBytes -= amount;
	}

	fclose(ofp);

	return 1;
}

