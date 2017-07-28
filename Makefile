build:
	gcc -Wall client.c -o client
	gcc -Wall selectserver.c -o server

clean:
	rm client server *.log
