/*
用于服务进程与nobody进程通信。nobody进程协助服务进程创建数据连接套接字
*/
#ifndef _PRIV_SOCK_H_
#define _PRIV_SOCK_H_

#include"session.h"

//内部进程自定义协议,用于FTP服务进程与nobody进程进行通信

//FTP服务进程向nobody进程请求的命令.
//PRIV_SOCK_GET_DATA_SOCK请求包：(PRIV_SOCK_GET_DATA_SOCK 1字节)  (端口  4字节)   (IP地址   不定长)
#define PRIV_SOCK_GET_DATA_SOCK  1   //获取port模式数据连接套接字.请求PORT模式数据套接字
//nobody进程协助被动模式建立数据连接接受的命令
#define PRIV_SOCK_PASV_ACTIV     2
#define PRIV_SOCK_PASV_LISTEN    3   //请求监听的命令
#define PRIV_SOCK_PASV_ACCEPT    4   //请求被动模式数据连接套接字

//nobody进程对FTP服务进程的应答
#define PRIV_SOCK_RESULT_OK   1
#define PRIV_SOCK_RESULT_BAD  2


void priv_sock_init(session_t *sess);
void priv_sock_close(session_t *sess);
void priv_sock_set_parent_context(session_t *sess);
void priv_sock_set_child_context(session_t *sess);

void priv_sock_send_cmd(int fd,char cmd);//发送命令，子->父  ftp福区进程发给nobody
char priv_sock_get_cmd(int fd);//接收命令，父<-子
void priv_sock_send_result(int fd,char res);//发送结果，父->子
char priv_sock_get_result(int fd);//接收结果，子<-父
void priv_sock_send_int(int fd,int the_int);//发送一个整数
int priv_sock_get_int(int fd);//接收一个整数
void priv_sock_send_buf(int fd,const char* buf,unsigned int len);//发送一个字符串
void priv_sock_recv_buf(int fd,char* buf,unsigned int len);//接收一个字符串
void priv_sock_send_fd(int sock_fd,int fd);//发送文件描述符
int priv_sock_recv_fd(int sock_fd);//接收文件描述符

#endif

