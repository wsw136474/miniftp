#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_
#include "common.h"

int getlocalip(char *ip);//获取本地IP地址

void activate_nonblock(int fd);
void deactivate_noblock(int fd);

int read_timeout(int fd,unsigned int wait_seconds);
int write_timeout(int fd,unsigned int wait_seconds);
int accept_timeout(int fd,struct sockaddr_in * addr,unsigned int wait_seconds);
int connect_timeout(int fd,struct sockaddr_in * addr,unsigned int wait_seconds);

ssize_t readn(int fd,void *buf,size_t count);
ssize_t writen(int fd, const void *buf, size_t count);
ssize_t recv_peek(int sockfd,void *buf,size_t len);
ssize_t readline(int sockfd,void * buf,size_t maxline);

void send_fd(int sock_fd,int send_fd);
int recv_fd(const int sock_fd);
//封装服务器创建连接基本函数，创建、绑定、监听
int tcp_server(const char *host, unsigned short port);
//封装获取文件权限和文件日期的函数
const  char *statbuf_get_perms(struct stat *sbuf);
const char* statbuf_get_date(struct stat *sbuf);
//对文件加读锁
int lock_file_read(int fd);
//对文件加写锁
int lock_file_write(int fd);
//解锁函数
int unlock_file(int fd);
int lock_internal(int fd,int lock_type);
int tcp_client(unsigned short port);
long get_time_sec(void);
long get_time_usec(void);
void nano_sleep(double seconds);

//用于abor命令,紧急模式，开启带外数据的接收
void  activate_oobinline(int fd);
///用于捕捉AIGURG，有紧急数据到，产生这个信号，发送给当前进程，接收紧急信号
void activate_sigurg(int fd);
#endif
