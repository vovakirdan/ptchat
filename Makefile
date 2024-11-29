# compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -O2 -g
LDFLAGS = -lssl -lcrypto

# project name
TARGET = ptchat

# source files and object files
SRCS = src/main.c src/auth.c src/message.c src/user.c src/utils.c src/network.c
OBJS = $(SRCS:.c=.o)

# default target
all: $(TARGET)

# build the target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# clean up
clean:
	rm -f $(TARGET) $(OBJS)

# run the server
run: $(TARGET)
	./$(TARGET) 8081