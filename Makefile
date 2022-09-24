TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build

CC=gcc
FLAGS = -pthread -g -ggdb -DDEBUG -I$(INC_DIR)
OBJS = $(BUILD_DIR)/tju_packet.o \
	   $(BUILD_DIR)/kernel.o \
	   $(BUILD_DIR)/tju_tcp.o 



default:all

all: pwd clean server client

pwd:
	@echo "current dir is $(shell pwd)"
	@echo $(TOP_DIR)
	@echo $(INC_DIR)
	@echo $(SRC_DIR)
	@echo $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c 
	$(CC) $(FLAGS) -c -o $@ $<

clean:
	-rm -f ./build/*.o client server

server: $(OBJS)
	$(CC) $(FLAGS) ./src/server.c -o server $(OBJS)

client:
	$(CC) $(FLAGS) ./src/client.c -o client $(OBJS) 



	
