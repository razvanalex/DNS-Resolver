build: 
	gcc -Wall main.c -o dnsclient

run:
	./dnsclient ${ARGS}

clean:
	rm -fr ./dnsclient
