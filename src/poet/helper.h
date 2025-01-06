#pragma once

#include<errno.h>
#include<error.h>
#include<stdbool.h>

#define BUF_LEN      1024
#define TIMEOUT      4000
#define SERVER_PORT 12345
#define ERROR(msg) error(true,  errno, "%s", (msg));
#define WARN(msg)  error(false, errno, "%s", (msg));

typedef unsigned char byte_t;
