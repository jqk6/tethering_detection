
all:
	gcc pcapParser.c -lpcap -o pcapParser
	gcc pcapParser2.c -lpcap -o pcapParser2