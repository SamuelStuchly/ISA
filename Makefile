
CC=g++
CFLAGS=-std=c++11

all: isa-tazatel
isa-tazatel: isa-tazatel.o
isa-tazatel.o: isa-tazatel.cpp 

clean:
	rm -f isa-tazatel isa-tazatel.o
run: isa-tazatel
	./isa-tazatel