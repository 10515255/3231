GCC = gcc -std=c99 -Wall -Werror -pedantic
all :
	rm -f client server
	$(GCC) -o client client.c -L"../netbase" -lnetbase -lssl
	$(GCC) -o server server.c -L"../netbase" -lnetbase -lssl

