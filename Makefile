PING=/home/bjori/Sources/mongoc/mongoc-ping
CFLAGS += -Wall -g -O0
INCLUDES = -I.
LFLAGS = -lpthread -lssl -lcrypto


SUPPRESS := @

app:
	@echo [CC] $@
	$(SUPPRESS) $(CC) $(CFLAGS) $(INCLUDES) -o $@ server.c $(LFLAGS) $(LIBS)

test:
	$(SUPPRESS) PING=${PING} sh test.sh

.PHONY: app test

all: app

