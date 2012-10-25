PROJ = cloudServer

NETBASE = ../netbase/libnetbase.a
LINKNETBASE = -L"../netbase" -lnetbase
GCC = gcc -std=c99 -Wall -Werror -pedantic

OBJ = cloudServer.o database.o cloudProtocol.o
HEADERS = database.h cloudProtocol.h

$(PROJ) : $(OBJ) $(HEADERS) $(NETBASE)
	$(GCC) -o $(PROJ) $(OBJ) $(LINKNETBASE) -lssl

cloudServer.o : cloudServer.c cloudProtocol.h
	$(GCC) -c cloudServer.c -lssl

database.o : database.c  
	$(GCC) -c database.c 

cloudProtocol.o : cloudProtocol.c cloudProtocol.h 
	$(GCC) -c cloudProtocol.c -lssl

#jump to the netbase folder, and run the makefile located there to build the netbase library
$(NETBASE) :
	make -C ../netbase/src

clean : 
	rm -f $(PROJ) $(OBJ)
