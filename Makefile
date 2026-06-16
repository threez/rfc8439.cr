.PHONY: all clean fmt fmtcheck lint fix docs spec bench bench-go version tag

UNAME_M != uname -m
NEON_OBJ != case "$(UNAME_M)" in arm64|aarch64) echo ext/chacha20_neon.o ;; esac

all: clean fmt lint docs spec

fmt:
	crystal tool format

fmtcheck:
	crystal tool format --check

# NEON C extension (aarch64 only)
ext/chacha20_neon.o: ext/chacha20_neon.c ext/chacha20_neon.h
	$(CC) -O3 -march=armv8-a+simd -c -o $@ $<

spec: $(NEON_OBJ)
	crystal spec -v

bench: $(NEON_OBJ)
	shards build --release
	./bin/bench-chacha2

bench-go:
	cd bench && go run chacha20_bench.go

lib/ameba/bin/ameba:
	shards install

lint: lib/ameba/bin/ameba
	lib/ameba/bin/ameba

fix: lib/ameba/bin/ameba
	lib/ameba/bin/ameba --fix

docs:
	crystal docs

clean:
	rm -rf docs/
	rm -rf bin
	rm -f ext/chacha20_neon.o

# Sync the VERSION constant in src/ to match shard.yml's version field.
# Bump shard.yml's version first, then run `make version`.
version:
	@V=$$(grep '^version:' shard.yml | sed -E 's/^version:[[:space:]]*//'); \
	for f in $$(grep -rl '^[[:space:]]*VERSION[[:space:]]*=[[:space:]]*"[^"]*"' src/ 2>/dev/null); do \
		sed -E "s/^([[:space:]]*VERSION[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\\1\"$$V\"/" "$$f" > "$$f.tmp" && mv "$$f.tmp" "$$f"; \
		echo "updated $$f to $$V"; \
	done

# Create an annotated git tag "vX.Y.Z" from shard.yml's version field.
tag:
	@V=$$(grep '^version:' shard.yml | sed -E 's/^version:[[:space:]]*//'); \
	git tag -a "v$$V" -m "Release v$$V"; \
	echo "tagged v$$V"
