CC      ?= gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=gnu11 -fno-strict-aliasing
ASFLAGS ?= -g

OBJS = memmap.o state.o signals.o blacklist.o length.o inject.o trampoline.o
LIB  = libinjector.a
BIN  = injector

.PHONY: all clean

all: $(LIB) $(BIN)

$(LIB): $(OBJS)
	ar rcs $@ $(OBJS)

$(BIN): main.o $(LIB)
	$(CC) $(CFLAGS) -o $@ main.o $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

trampoline.o: trampoline.S
	$(CC) $(ASFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(LIB) $(BIN)
