CC=g++
CFLAGS=-march=native -std=c++11 -O2 -pthread -funroll-loops -maes -msse4.2 -mavx2
INCLUDE_PATH=-I. -I../ -I/home/$(USER)/Hermes/include -I../include -I/usr/local/include

ZEROMQ_LIB=-L/home/$(USER)/Hermes/lib 
GMP_LIB=-L/home/$(USER)/Hermes/lib 
OPENSSL_LIB=-L/usr/local/lib 
PBC_LIB=-L/home/$(USER)/Hermes/lib

DEPS=$(ZEROMQ_LIB) $(GMP_LIB) $(OPENSSL_LIB) $(PBC_LIB)
LIBS=-lzmq -lgmp -lm -lcrypto -lpbc 

.PHONY: server client all clean

all:
	cd server; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o server $(LD_FLAGS) $(DEPS) $(LIBS)
	cd client; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o client $(LD_FLAGS) $(DEPS) $(LIBS)

server:
	cd server; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o server $(LD_FLAGS) $(DEPS) $(LIBS)

client:
	cd client; $(CC) $(CFLAGS) $(INCLUDE_PATH) *.cpp -o client $(LD_FLAGS) $(DEPS) $(LIBS)

clean:
	cd server; rm -f server
	cd client; rm -f client


