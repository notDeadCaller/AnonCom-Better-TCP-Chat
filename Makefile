# Compiler and flags
CC = gcc
CFLAGS = -I ./liboqs/build/include -pthread -g -Wall
LDFLAGS = -L ./liboqs/build/lib
LIBS = -loqs -lssl -lcrypto -lncurses

# Target executables
TARGET_SERVER = server
TARGET_CLIENT = client

# Default rule: 'make' or 'make all' will build both
all: $(TARGET_SERVER) $(TARGET_CLIENT)

# Rule to build the server
$(TARGET_SERVER): server.c
	$(CC) serverTest.c -o $(TARGET_SERVER) $(CFLAGS) $(LDFLAGS) $(LIBS)

# Rule to build the client
$(TARGET_CLIENT): client.c
	$(CC) clientTest.c -o $(TARGET_CLIENT) $(CFLAGS) $(LDFLAGS) $(LIBS)

# Rule to clean up compiled files
clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT) *.o
