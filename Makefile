CFLAGS += -Wall -g -O0
INCLUDES = -I.
LFLAGS = -lpthread -lssl -lcrypto


SUPPRESS := @

app:
	@echo [CC] $@
	$(SUPPRESS) $(CC) $(CFLAGS) $(INCLUDES) -o $@ server.c $(LFLAGS) $(LIBS)

.PHONY: app

all: app

