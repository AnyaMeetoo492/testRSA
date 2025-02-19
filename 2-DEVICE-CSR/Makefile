TARGET = device-gen-csr
LIBS = -lm -ldl -lrt -lmbedx509 -lmbedtls -lmbedcrypto 
EXTLIBSDIR = ../ext/lib/
EXTINCSDIR = ../ext/include/
CC = gcc
CFLAGS = -g -Wall

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) -I$(EXTINCSDIR) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -L$(EXTLIBSDIR) -o $@

clean:
	-rm -f *.o
	-rm -f *.pem
	-rm -f $(TARGET)
