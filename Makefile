CLIENT = client.exe
SERVER = server.exe

CLIENTOBJ = sslClient.o sslCommunicate.o
SERVEROBJ = sslServer.o sslCommunicate.o

C99 = gcc -std=c99 
CFLAGS = -Wall -Werror -pedantic

all : $(CLIENT) $(SERVER)

$(CLIENT) : $(CLIENTOBJ) 
	$(C99) $(CFLAGS) -o $(CLIENT) $(CLIENTOBJ) -lssl

$(SERVER) : $(SERVEROBJ)
	$(C99) $(CFLAGS) -o $(SERVER) $(SERVEROBJ) -lssl

sslClient.o : sslClient.c 
	$(C99) $(CFLAGS) -c sslClient.c

sslServer.o : sslServer.c 
	$(C99) $(CFLAGS) -c sslServer.c

sslCommunicate.o : sslCommunicate.c sslCommunicate.h
	$(C99) $(CFLAGS) -c sslCommunicate.c

clean :
	rm -f $(CLIENT) $(SERVER) $(CLIENTOBJ) $(SERVEROBJ)
