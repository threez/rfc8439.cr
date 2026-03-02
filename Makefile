.PHONY: fmt fix lint spec docs clean bench

UNAME_M := $(shell uname -m)

all: clean fmt fix docs spec

fmt:
	crystal tool format

# NEON C extension (aarch64 only)
ifeq ($(UNAME_M),arm64)
NEON_OBJ = ext/chacha20_neon.o
ext/chacha20_neon.o: ext/chacha20_neon.c ext/chacha20_neon.h
	$(CC) -O3 -march=armv8-a+simd -c -o $@ $<
else ifeq ($(UNAME_M),aarch64)
NEON_OBJ = ext/chacha20_neon.o
ext/chacha20_neon.o: ext/chacha20_neon.c ext/chacha20_neon.h
	$(CC) -O3 -march=armv8-a+simd -c -o $@ $<
else
NEON_OBJ =
endif

spec: $(NEON_OBJ)
	crystal spec -v

bench: $(NEON_OBJ)
	shards build --release
	./bin/bench-chacha2

bench-go:
	cd bench && go run chacha20_bench.go

AMEBA=./lib/ameba/bin/ameba

$(AMEBA): $(AMEBA).cr
	crystal build -o $@ $(AMEBA).cr

fix:
	$(AMEBA) --fix

lint: $(AMEBA)
	$(AMEBA)

docs:
	crystal docs

clean:
	rm -rf bin
	rm -rf docs
	rm -f ext/chacha20_neon.o
