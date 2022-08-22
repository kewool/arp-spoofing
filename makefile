LDLIBS=-lpcap -lpthread

all: arp_spoofing

arp_spoofing: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o

clean:
	rm -f arp_spoofing *.o
