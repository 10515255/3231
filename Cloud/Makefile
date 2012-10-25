PROJ = cloudServer

NETBASE = ../netbase/libnetbase.a
LINKNETBASE = -L"../netbase" -lnetbase
GCC = gcc -std=c99 -Wall -Werror -pedantic

OBJ = cloud.o database.o
HEADERS = database.h

$(PROJ) : $(OBJ) $(HEADERS) $(NETBASE)
	$(GCC) -o $(PROJ) $(OBJ) $(LINKNETBASE) -lssl

cloud.o : cloud.c $(NETBASE)
	$(GCC) -c cloud.c -lssl

database.o : database.c  
	$(GCC) -c database.c 

#jump to the netbase folder, and run the makefile located there to build the netbase library
$(NETBASE) :
	make -C ../netbase/src

clean : 
	rm -f $(PROJ) $(OBJ)
