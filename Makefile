.PHONY: fmt fix lint spec docs clean

all: clean fmt fix docs spec

fmt:
	crystal tool format

spec:
	crystal spec -v

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
