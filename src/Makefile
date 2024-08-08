# Define the compiler
CC = gcc

# Define the compiler flags
CFLAGS = -Wall -g

# Find all .c files in the current directory
SOURCES = $(wildcard *.c)

# Define the object files
OBJECTS = $(SOURCES:.c=.o)

# Default target to compile all .c files to .o files
all: $(OBJECTS)

# Rule to compile each .c file to .o file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJECTS)
