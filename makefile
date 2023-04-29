CC = gcc
CFLAGS = -Wall -Wextra -pedantic
SRCDIR = src
OBJDIR = build
EXECDIR = bin
TESTDIR = tests
TESTSRCDIR = $(TESTDIR)
TESTOBJDIR = $(TESTDIR)/build
TESTEXECDIR = $(TESTDIR)/bin
LDFLAGS = -lcrypto

CLIENT_SOURCES = $(SRCDIR)/client.c $(SRCDIR)/message.c
SERVER_SOURCES = $(SRCDIR)/server.c $(SRCDIR)/message.c $(SRCDIR)/signature_utils.c
UTILS_SOURCES = $(SRCDIR)/signature_utils.c

CLIENT_OBJECTS = $(CLIENT_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
SERVER_OBJECTS = $(SERVER_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
UTILS_OBJECTS = $(UTILS_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

CLIENT_EXECUTABLE = $(EXECDIR)/client
SERVER_EXECUTABLE = $(EXECDIR)/server

TEST_SOURCES = $(TESTSRCDIR)/tests.c $(TESTSRCDIR)/unity.c $(SRCDIR)/message.c
TEST_OBJECTS = $(TEST_SOURCES:$(TESTSRCDIR)/%.c=$(TESTOBJDIR)/%.o)
TEST_EXECUTABLE = $(TESTEXECDIR)/tests

.PHONY: all clean tests run_tests

all: $(CLIENT_EXECUTABLE) $(SERVER_EXECUTABLE) $(TEST_EXECUTABLE)

$(CLIENT_EXECUTABLE): $(CLIENT_OBJECTS) | $(EXECDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(SERVER_EXECUTABLE): $(SERVER_OBJECTS) $(UTILS_OBJECTS) | $(EXECDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -pthread

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

$(TESTOBJDIR)/%.o: $(TESTSRCDIR)/%.c | $(TESTOBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@ -I$(SRCDIR)

$(TEST_EXECUTABLE): $(TEST_OBJECTS) $(UTILS_OBJECTS) | $(TESTEXECDIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -pthread -I$(SRCDIR)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(EXECDIR):
	mkdir -p $(EXECDIR)

$(TESTOBJDIR):
	mkdir -p $(TESTOBJDIR)

$(TESTEXECDIR):
	mkdir -p $(TESTEXECDIR)

.PHONY: all clean tests run_tests

run_tests: $(TEST_EXECUTABLE)
	$(TEST_EXECUTABLE) 2> /dev/null

clean:
	rm -rf $(OBJDIR) $(EXECDIR) $(TESTOBJDIR) $(TESTEXECDIR)

