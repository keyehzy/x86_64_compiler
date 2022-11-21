CC=gcc
CFLAGS=-W -Wall -Wextra -g3 -ggdb3 -O0 -Wconversion

SRCS=buffer.c

main : main.c $(SRCS)

clean :
	$(RM) main *.o
