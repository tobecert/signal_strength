all: signal-strength

signal-strength: signal-strength.o
	gcc -o signal-strength signal-strength.o -lpcap -pthread
signal-strength.o: main.h main.c
	gcc -c -o signal-strength.o main.c -lpcap -pthread

clean:
	rm -f signal-strength
	rm -f *.o
