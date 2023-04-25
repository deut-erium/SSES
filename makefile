CC=gcc
CFLAGS=-Wall -Wextra -pthread -I.

multi_server: multi_server.o message.o
	$(CC) $(CFLAGS) -o $@ $^

client: client.o message.o
	$(CC) $(CFLAGS) -o $@ $^

main: main.o
	$(CC) $(CFLAGS) -lcrypto -o $@ $^

multi_server.o: multi_server.c message.h
	$(CC) $(CFLAGS) -c $<

client.o: client.c message.h
	$(CC) $(CFLAGS) -c $<

message.o: message.c message.h
	$(CC) $(CFLAGS) -c $<

main.o: main.c
	$(CC) $(CFLAGS) -c $<

.PHONY: clean

clean:
	rm -f multi_server client main *.o

