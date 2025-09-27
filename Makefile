# Build with: make        # -> ./AES_Functions
# Clean with: make clean

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11

TARGET  := AES_Functions
OBJS    := main.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

clean:
	rm -f $(OBJS) $(TARGET)
