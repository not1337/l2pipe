l2pipe: l2pipe.c
	gcc -O3 -Wall -s -o l2pipe l2pipe.c -lpthread -llz4

clean:
	rm -f l2pipe core *.o
