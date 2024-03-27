all: pcap-test

pcap-test: pcap-test.o
	gcc -o pcap-test pcap-test.o -lpcap

pcap-test.o: pcap-test.c
	gcc -g -c -o pcap-test.o pcap-test.c -lpcap

clean:
	rm -f pcap-test *.o


