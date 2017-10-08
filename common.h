#ifndef _COMMON_H_
#define _COMMON_H_


#define ERR_EXIT(m)\
	do\
	{\
		perror(m);\
		exit(EXIT_FAILURE);\
	}while(0)

#include<unistd.h>
#include<errno.h>
#include<stdlib.h>
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include <netdb.h>
#include<fcntl.h>
#include<string.h>
#include<arpa/inet.h>
#include<time.h>
#include <sys/types.h>
#include <pwd.h>
#include<ctype.h>
#include <shadow.h>
#include <crypt.h>
#include<sys/stat.h>
#include<dirent.h>
#include<sys/time.h>
#include<signal.h>
#include <sys/sendfile.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#define MAX_COMMAND_LINE  1024
#define MAX_COMMAND     32
#define MAX_ARG   1024
#define MINIFTP_CONF   "miniftpd.conf"   //配置文件路径。发布时改为/etc目录下
#endif
