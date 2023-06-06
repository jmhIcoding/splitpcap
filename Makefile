all:
	cd src && $(MAKE)
	cp src/splitpcap ./
	cp src/splitpcap bin/
clean: 
	rm -f splitpcap
