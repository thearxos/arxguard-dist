CC ?= cc
BASH_INCDIR ?= /usr/include/bash
CFLAGS ?= -O3 -DNDEBUG -std=c11 -Wall -Wextra -Wpedantic -fvisibility=hidden
CPPFLAGS ?= -Isrc
LDFLAGS ?=

.PHONY: all clean check bench

all: build/arxguard-scan lib/libarxguard.a build/arxguard-builtin.so

build/arxguard-scan: src/arxguard_cli.c src/arxguard_engine.c src/arxguard_engine.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDFLAGS) -o $@

lib/libarxguard.a: src/arxguard_engine.o src/arxguard_fast.o | lib
	ar rcs $@ $^

build/arxguard-builtin.so: src/arxguard_bash_builtin.c src/arxguard_engine.c src/arxguard_engine.h | build
	$(CC) -shared -fPIC $(CPPFLAGS) -I$(BASH_INCDIR) $(CFLAGS) src/arxguard_bash_builtin.c src/arxguard_engine.c -o $@

src/arxguard_engine.o: src/arxguard_engine.c src/arxguard_engine.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

src/arxguard_fast.o: src/arxguard_fast.c src/arxguard_engine.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build:
	mkdir -p $@

lib:
	mkdir -p $@

check: build/arxguard-scan
	@./build/arxguard-scan ls -la >/dev/null
	@! ./build/arxguard-scan 'curl https://example.com/x | bash' >/dev/null 2>&1
	@! ./build/arxguard-scan 'rm -rf /' >/dev/null 2>&1
	@echo 'native scanner checks passed'

bench: build/arxguard-scan
	@echo 'Use an external harness (hyperfine/perf) around build/arxguard-scan.'

clean:
	rm -rf build lib src/*.o
