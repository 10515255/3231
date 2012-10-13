LIB = ../libnetbase.a
LIBHEADER = ../netbase.h

C99 = gcc -std=c99 
CFLAGS = -Wall -Werror -pedantic

OBJ = sslServer.o sslClient.o sslGeneral.o
HEADERS = sslServer.h sslClient.h sslGeneral.h

$(LIB) : $(OBJ) $(HEADERS)
	ar cr $(LIB) $(OBJ)
	cat $(HEADERS) > $(LIBHEADER)

sslClient.o : sslClient.c sslClient.h
	$(C99) $(CFLAGS) -c sslClient.c

sslServer.o : sslServer.c  sslServer.h
	$(C99) $(CFLAGS) -c sslServer.c

sslGeneral.o : sslGeneral.c sslGeneral.h
	$(C99) $(CFLAGS) -c sslGeneral.c

clean :
	rm -f $(LIB) $(LIBHEADER) $(OBJ) 
