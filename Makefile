CC=gcc
CFLAGS=-c -g -Wall
OBJ=obj-files/
OUT=out/
BIN_NAME=elf_dumper
HDR=headers/
SRC=src/
TEST=test/
CWD=$(shell pwd)
DEB_FLAGS=-g -Wall

.PHONY: clean

all: dirs $(OUT)$(BIN_NAME) $(TEST)host $(TEST)host-no-pie $(TEST)host_hello_world $(TEST)host_hello_world-no-pie \
	$(TEST)host_hello_world_32 $(TEST)host_hello_world_32-no-pie

dirs:
	mkdir -p $(OBJ)
	mkdir -p $(OUT)

$(OUT)$(BIN_NAME): $(OBJ)elf_parser.o $(OBJ)ptrace_utils.o $(OBJ)memory_management.o $(OBJ)logger.o $(OBJ)dumper.o $(OBJ)main.o
	$(CC) $(DEB_FLAGS) -I $(HDR) -o $@ $^

$(OBJ)main.o: main.c
	$(CC) $(DEB_FLAGS) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)dumper.o: $(SRC)dumper.c
	$(CC) $(DEB_FLAGS) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)logger.o: $(SRC)logger.c
	$(CC) $(DEB_FLAGS) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)memory_management.o: $(SRC)memory_management.c
	$(CC) $(DEB_FLAGS) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)ptrace_utils.o: $(SRC)ptrace_utils.c
	$(CC) $(DEB_FLAGS) -I $(HDR) $(CFLAGS) -o $@ $<

$(OBJ)elf_parser.o: $(SRC)elf_parser.c
	$(CC) $(DEB_FLAGS) -I $(HDR) $(CFLAGS) -o $@ $<

$(TEST)host: $(TEST)host.c
	$(CC) -o $@ $<

$(TEST)host-no-pie: $(TEST)host.c
	$(CC) -no-pie -o $@ $<

$(TEST)host_hello_world: $(TEST)host_hello_world.c
	$(CC) -o $@ $<

$(TEST)host_hello_world-no-pie: $(TEST)host_hello_world.c
	$(CC) -no-pie -o $@ $<

$(TEST)host_hello_world_32: $(TEST)host_hello_world.c
	$(CC) -m32 -o $@ $<

$(TEST)host_hello_world_32-no-pie: $(TEST)host_hello_world.c
	$(CC) -m32 -no-pie -o $@ $<

clean:
	rm -rf $(OBJ)
	rm -rf $(OUT)