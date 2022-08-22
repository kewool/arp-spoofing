LDLIBS=-lpcap -lpthread

all: send-arp-test

send-arp-test: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o

clean:
	rm -f arp_spoofing *.o
