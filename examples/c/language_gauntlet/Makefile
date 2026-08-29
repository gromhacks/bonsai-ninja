CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic
SOURCES := $(shell find src -name '*.c' -print)

.PHONY: all clean
all: language-gauntlet

language-gauntlet: $(SOURCES)
	$(CC) $(CFLAGS) -Iinclude $(SOURCES) -o $@

clean:
	rm -f language-gauntlet
