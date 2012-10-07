CLIENT = client
SERVER = server

C99 = gcc -std=c99 
CFLAGS = -Wall -Werror -pedantic

all : $(CLIENT) $(SERVER)

$(CLIENT) : sslClient.c
	$(C99) $(CFLAGS) -o $(CLIENT) sslClient.c -lssl

$(SERVER) : sslServer.c
	$(C99) $(CFLAGS) -o $(SERVER) sslServer.c -lssl

clean :
	rm -f sslClient.o sslServer.o $(CLIENT) $(SERVER)
