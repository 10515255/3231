PROJ = client 

NETBASE = ../netbase/libnetbase.a
LINKNETBASE = -L"../netbase" -lnetbase
GCC = gcc -g -std=c99 -Wall -Werror -pedantic

OBJ = user.o database.o ../Cloud/cloudProtocol.o ../Cloud/database.o
HEADERS = database.h

$(PROJ) : $(OBJ) $(HEADERS) $(NETBASE) bankUser
	$(GCC) -o $(PROJ) $(OBJ) $(LINKNETBASE) -lssl

user.o : user.c ../Cloud/cloudProtocol.h 
	$(GCC) -c user.c -lssl

database.o : database.c  
	$(GCC) -c database.c

../Cloud/cloudProtocol.o : ../Cloud/cloudProtocol.c  ../Cloud/database.c ../Cloud/cloudProtocol.h
	$(GCC) -o ../Cloud/cloudProtocol.o -c ../Cloud/cloudProtocol.c

../Cloud/database.o : ../Cloud/database.c ../Cloud/database.h
	$(GCC) -o ../Cloud/database.o -c ../Cloud/database.c

bankUser : bankUser.c
	gcc -std=c99 -o bankUser bankUser.c -L"../netbase" -lnetbase -lssl

#jump to the netbase folder, and run the makefile located there to build the netbase library
$(NETBASE) :
	make -C ../netbase/src

clean : 
	rm -f $(PROJ) $(OBJ) bankUser
