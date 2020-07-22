
all:
	gcc -D_REENTRANT scanner.c -O3 -o scanner -lpthread

clean:
	rm -vf scanner
