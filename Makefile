# Makefile for cryptor.c

CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = cryptor
SRC = cryptor.c

RUN_TARGET = run_in_mem
RUN_SRC = run_in_mem.c

$(RUN_TARGET): $(RUN_SRC)
	$(CC) $(CFLAGS) -o $(RUN_TARGET) $(RUN_SRC) $(SRC)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)