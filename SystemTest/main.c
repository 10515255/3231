#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <dirent.h>

void ls() {
	DIR *dir = opendir("./");
	if(dir == NULL) {
		fprintf(stderr, "Could not list the directory.\n");
		return;
	}

	struct dirent *entry;
	//need to explicitly check errno before and after to detect error?
	while(entry = readdir(dir)) {
		printf("%s\n", entry->d_name);
	}

	closedir(dir);
}

void respondTo(char *request) {
	if(strcmp(request, "ls") == 0) {
		ls();
	}
	else if(strcmp(request, "pwd") == 0) {
		printf("present working directory\n");
	}
}

int main(int argc, char **argv) {
	char buffer[1024];
	while(fgets(buffer, sizeof(buffer), stdin) != NULL) {
		//overwrite the newline with a terminal
		buffer[strlen(buffer)-1] = '\0';
		printf("%s\n", buffer);
		respondTo(buffer);
	}

	printf("Thanks for coming,\n");
	exit(EXIT_SUCCESS);
}
