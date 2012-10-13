LIB = ../netbase.a 
LIBHEADER = ../netbase.h

OBJ = sslClient.o sslServer.o sslCommunicate.o
HEADERS = sslClient.h sslServer.h sslCommunicate.h

C99 = gcc -std=c99 
CFLAGS = -Wall -Werror -pedantic

$(LIB) : $(OBJ) $(HEADERS)
	ar cr $(LIB) $(OBJ)
	cat $(HEADERS) > $(LIBHEADER)


sslClient.o : sslClient.c 
	$(C99) $(CFLAGS) -c sslClient.c

sslServer.o : sslServer.c 
	$(C99) $(CFLAGS) -c sslServer.c

sslCommunicate.o : sslCommunicate.c sslCommunicate.h
	$(C99) $(CFLAGS) -c sslCommunicate.c

clean :
	rm -f $(LIB) $(LIBHEADER) $(OBJ) 
