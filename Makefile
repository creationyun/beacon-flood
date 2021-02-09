LDLIBS=-lpcap

all: beacon-flood

beacon-flood: main.o net-address.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f beacon-flood *.o


