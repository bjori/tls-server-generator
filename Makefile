PING=/home/bjori/Sources/mongoc/mongoc-ping
CFLAGS += -Wall -g -O0
INCLUDES = -I.
LFLAGS = -lpthread -lssl -lcrypto


SUPPRESS := @

app:
	@echo [CC] $@
	$(SUPPRESS) $(CC) $(CFLAGS) $(INCLUDES) -o $@ server.c mongoc-b64.c $(LFLAGS) $(LIBS)

test: app
	$(SUPPRESS) PING=${PING} sh test.sh

debug: app
	$(SUPPRESS) gdb --args app 8888 27017

.PHONY: app test

all: app

