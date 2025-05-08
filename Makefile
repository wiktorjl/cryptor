# Makefile for cryptor.c

CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET_CRYPT = cryptor
TARGET_CRYPT_SRC = cryptor.c
TARGET_CRYPT_OBJ = cryptor.o

TARGET_RUN = decryptor
TARGET_RUN_SRC = decryptor.c

$(TARGET_RUN): $(TARGET_RUN_SRC)
	$(CC) $(CFLAGS) -c $(TARGET_CRYPT_SRC)
	$(CC) $(CFLAGS) -o $(TARGET_RUN) $(TARGET_CRYPT_OBJ) $(TARGET_RUN_SRC)


$(TARGET_CRYPT): $(TARGET_CRYPT_SRC)
	$(CC) $(CFLAGS) -DCRYPTOR_STANDALONE -o $(TARGET_CRYPT) $(TARGET_CRYPT_SRC)

all: $(TARGET_CRYPT) $(TARGET_RUN)

clean:
	rm -f $(TARGET_CRYPT)
	rm -f $(TARGET_RUN)
	rm -f $(TARGET_CRYPT_OBJ)
	rm -f payload.h