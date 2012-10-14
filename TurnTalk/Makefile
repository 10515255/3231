CLIENT = client
SERVER = server

NETBASE = ../netbase/libnetbase.a
LINKNETBASE = -L"../netbase" -lnetbase
GCC = gcc -std=c99 -Wall -Werror -pedantic


all : $(CLIENT) $(SERVER)

$(CLIENT) : client.c $(NETBASE) 
	$(GCC) -o client client.c $(LINKNETBASE) -lssl

$(SERVER) : server.c $(NETBASE)
	$(GCC) -o server server.c $(LINKNETBASE) -lssl

#jump to the netbase folder, and run the makefile located there to build the netbase library
$(NETBASE) :
	make -C ../netbase/src

clean : 
	rm -f $(CLIENT) $(SERVER)
