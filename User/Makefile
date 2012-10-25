PROJ = client 

NETBASE = ../netbase/libnetbase.a
LINKNETBASE = -L"../netbase" -lnetbase
GCC = gcc -g -std=c99 -Wall -Werror -pedantic

OBJ = user.o database.o
HEADERS = database.h

$(PROJ) : $(OBJ) $(HEADERS) $(NETBASE)
	$(GCC) -o $(PROJ) $(OBJ) $(LINKNETBASE) -lssl

user.o : user.c $(NETBASE)
	$(GCC) -c user.c -lssl

database.o : database.c  
	$(GCC) -c database.c 

#jump to the netbase folder, and run the makefile located there to build the netbase library
$(NETBASE) :
	make -C ../netbase/src

clean : 
	rm -f $(PROJ) $(OBJ)
