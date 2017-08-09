PROG = phoneproxy

SRCDIR = .
sources := server.c client.c common.c

CC = gcc


LIB += -lpthread
TARGET1 = server
TARGET2 = client

PROG : $(TARGET1) $(TARGET2)
	
$(TARGET1): server.c common.c utility.c common.h
	$(CC) $^ $(LIB) -o $@ -g

$(TARGET2): client.c common.c
	$(CC) $^ $(LIB) -o $@

.PHONEY : clean

clean:
	-rm *.o
