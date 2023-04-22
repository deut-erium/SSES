C=gcc
CFLAGS=-Wall -Werror
LIBS=-lssl -lcrypto

server: main.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f *.o server

