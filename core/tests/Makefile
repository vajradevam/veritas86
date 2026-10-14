CC     ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -std=gnu11

INJDIR = ../injector
LIB    = $(INJDIR)/libinjector.a

.PHONY: all clean

all: smoke

$(LIB):
	$(MAKE) -C $(INJDIR)

smoke: smoke.c $(LIB)
	$(CC) $(CFLAGS) -I$(INJDIR) -o $@ smoke.c $(LIB)

clean:
	rm -f smoke
