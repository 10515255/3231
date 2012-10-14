GCC = gcc -std=c99 -Wall -Werror -pedantic 
all : server client
server : server.c
	$(GCC) -o server server.c -L"../netbase" -lnetbase -lssl
client : client.c
	$(GCC) -o client client.c -L"../netbase" -lnetbase -lssl
clean :
	rm -f server client
