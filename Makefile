CC=g++
CFLAGS= -march=native 
LIB= -O3 -lgmp -lssl -lcrypto
SOURCES= sha.cpp
all: 
	$(CC) -o test $(SOURCES) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 