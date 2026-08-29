CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic
SOURCES := $(shell find src -name '*.cpp' -print)

.PHONY: all clean
all: language-gauntlet

language-gauntlet: $(SOURCES)
	$(CXX) $(CXXFLAGS) -Iinclude $(SOURCES) -o $@

clean:
	rm -f language-gauntlet
