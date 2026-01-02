CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
LDFLAGS =
SRC = main.c builder.c sender.c json_util.c utils.c cJSON.c
OBJ = $(SRC:.c=.o)
BIN = sendpkt

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
