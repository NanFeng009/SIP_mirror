#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "utility.h"

void error(char *msg);
extern char mid_msg[256];

#define true 1
#define false 0
#endif
