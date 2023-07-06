CC = /usr/bin/gcc
CFLAGS = -Wall -Werror -g
INCLUDES = -Iinclude
LDFLAGS = -lcrypto -lssl -lcjson

# source files and directories
SRC_DIR = src
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Object files and directories
OBJ_DIR = obj
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Executable file and directories
BIN_DIR = bin
TARGET = $(BIN_DIR)/tls-client

# Rules
all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
