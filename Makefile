all:
	gcc -o portstealer portstealer.c -lpcap

clean:
	rm portstealer

