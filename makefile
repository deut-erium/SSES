CC = gcc
CFLAGS = -Wall -Wextra -pedantic
SRCDIR = src
OBJDIR = build
EXECDIR = bin
LDFLAGS = -lcrypto

CLIENT_SOURCES = $(SRCDIR)/client.c $(SRCDIR)/message.c
SERVER_SOURCES = $(SRCDIR)/server.c $(SRCDIR)/message.c $(SRCDIR)/signature_utils.c
UTILS_SOURCES = $(SRCDIR)/signature_utils.c

CLIENT_OBJECTS = $(CLIENT_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
SERVER_OBJECTS = $(SERVER_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
UTILS_OBJECTS = $(UTILS_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

CLIENT_EXECUTABLE = $(EXECDIR)/client
SERVER_EXECUTABLE = $(EXECDIR)/server

.PHONY: all clean

all: $(CLIENT_EXECUTABLE) $(SERVER_EXECUTABLE)

$(CLIENT_EXECUTABLE): $(CLIENT_OBJECTS) | $(EXECDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(SERVER_EXECUTABLE): $(SERVER_OBJECTS) $(UTILS_OBJECTS) | $(EXECDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -pthread

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(EXECDIR):
	mkdir -p $(EXECDIR)

clean:
	rm -rf $(OBJDIR) $(EXECDIR)

