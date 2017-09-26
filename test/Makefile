# 目标模式，debug/release
# #VERSION = release
VERSION = debug

ifeq ($(VERSION), release)
	C_FLAGS = -O2 -Wall -D VS_DEBUG
else
	C_FLAGS = -g -Wall
endif

# 编译器类型
CC = gcc
CXX = g++

# 生成头文件
$(shell makeheader *.[ch])

# 当前工作目录
CUR_DIR = $(shell pwd)

# 动态库加载选项
LIB += -lpthread 
LIB += -lpcap

# 二进制文件安装目录
BIN = ./bin

# 目标依赖集
OBJS = $(wildcard *.c)

# 编译的目标
TARGET1 = mirror

all : $(TARGET1) 
$(TARGET1):$(OBJS) 
	$(CC) $(C_FLAGS) $^ $(LIB) -o $@

%.o:%.c
	$(CC) $(C_FLAGS) -c $< -o $@


.PHONEY : clean
	clean:
	-rm *.bak
	-rm *.o


#send_pack.c utility.c read_pack.c -lpcap
#gcc sniff_pack.c utility.c read_pack.c sip_handle.c sip_parser.c -lpcap
#gcc sniff_pack.c utility.c read_pack.c -lpcap
