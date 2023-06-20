CC=g++
CFLAGS= -march=native 
LIB= -O3 -lgmp -lssl -lcrypto
SOURCES= DSA.cpp
all: 
	$(CC) -o test $(SOURCES) $(LIB) $(CFLAGS) 
clean: 
	rm *.o 