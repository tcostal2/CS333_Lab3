CFLAGS = -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls  -Wmissing-declarations -Wold-style-definition \
-Wmissing-prototypes -Wdeclaration-after-statement \
-Wno-return-local-addr -Wunsafe-loop-optimizations -Wuninitialized -Werror -g3

CC = gcc
PROG = desplodocus_mt

all: $(PROG)

$(PROG): $(PROG).o
	$(CC) $(CFLAGS) -o $@ $^ -lz -lcrypt

$(PROG).o: $(PROG).c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(PROG) *~ \#*
