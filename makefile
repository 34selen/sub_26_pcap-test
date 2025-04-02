LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.c pcap-test.h

clean:
	rm -f pcap-test *.o
