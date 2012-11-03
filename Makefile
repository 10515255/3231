clean :
	#clean all directories
	make clean -C netbase/src/
	make clean -C Bank/
	make clean -C User/
	make clean -C Cloud/

	#rebuild, starting with netbase
	make -C netbase/src/
	make -C Bank/
	make -C User/
	make -C Cloud/

