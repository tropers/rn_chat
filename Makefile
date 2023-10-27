# Makefile for chat application
CC=gcc
CFLAGS=-g -Wall
OBJECTS=obj/chat_handler.o obj/main.o
LIBS=-lpthread

# --- targets
all: chat
chat: $(OBJECTS) 
	mkdir -p bin/
	$(CC) $(CFLAGS) -o bin/chat $(OBJECTS) $(LIBS)

obj/chat_handler.o: src/chat_handler.c
	mkdir -p obj/
	$(CC) $(CFLAGS) -c src/chat_handler.c -o obj/chat_handler.o

obj/main.o: src/main.c
	mkdir -p obj/
	$(CC) $(CFLAGS) -c src/main.c -o obj/main.o

# --- remove binary and executable files
clean:
	rm -f bin/* $(OBJECTS)
