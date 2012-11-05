PROJ = cloudServer

NETBASE = ../netbase/libnetbase.a
LINKNETBASE = -L"../netbase" -lnetbase
GCC = gcc -std=c99 -Wall -Werror -pedantic

OBJ = cloudServer.o database.o cloudProtocol.o ../User/database.o ../Bank/dollars.o
HEADERS = database.h cloudProtocol.h ../User/database.h ../Bank/dollars.h

$(PROJ) : $(OBJ) $(HEADERS) $(NETBASE)
	$(GCC) -o $(PROJ) $(OBJ) $(LINKNETBASE) -lssl

cloudServer.o : cloudServer.c cloudProtocol.h
	$(GCC) -c cloudServer.c -lssl

database.o : database.c database.h
	$(GCC) -c database.c 

cloudProtocol.o : cloudProtocol.c cloudProtocol.h 
	$(GCC) -c cloudProtocol.c -lssl

../User/database.o : ../User/database.c ../User/database.h
	$(GCC) -o ../User/database.o -c ../User/database.c

../Bank/dollars.o : ../Bank/dollars.c ../Bank/dollars.h
	$(GCC) -o ../Bank/dollars.o -c ../Bank/dollars.c

#jump to the netbase folder, and run the makefile located there to build the netbase library
$(NETBASE) :
	make -C ../netbase/src

clean : 
	rm -f $(PROJ) $(OBJ)
