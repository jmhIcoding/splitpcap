all:
	cd src && $(MAKE)
	cp src/nflog2eth ./
	cp src/nflog2eth bin/
clean: 
	rm -f nflog2eth
