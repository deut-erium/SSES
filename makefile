CC=gcc
CFLAGS=-I.
LIBS=-lpthread -lcrypto

multi_server: multi_server.o message.o
	$(CC) -o multi_server multi_server.o message.o $(LIBS)

multi_server.o: multi_server.c message.h
	$(CC) -c multi_server.c $(CFLAGS)

message.o: message.c message.h
	$(CC) -c message.c $(CFLAGS)

client: client.o message.o
	$(CC) -o client client.o message.o $(LIBS)

client.o: client.c message.h
	$(CC) -c client.c $(CFLAGS)

main: main.o
	$(CC) -o main main.o $(LIBS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS)

main_server: main_server.o message.o signature_utils.o
	$(CC) -o main_server main_server.o message.o signature_utils.o $(LIBS)

main_server.o: main_server.c message.h signature_utils.h
	$(CC) -c main_server.c $(CFLAGS)

signature_utils.o: signature_utils.c signature_utils.h
	$(CC) -c signature_utils.c $(CFLAGS)

clean:
	rm -f *.o multi_server client main main_server

