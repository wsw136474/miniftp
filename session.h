#ifndef _SESSION_H_
#define _SESSION_H_
#include "common.h"
typedef struct session
{
	//控制连接
	uid_t uid;//用户ID
	int ctrl_fd;//控制连接套接字
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];//命令行参数
	//数据连接
	struct sockaddr_in* port_addr;//保存客户端发送的地址
	int data_fd;//数据连接套接字
	int pasv_listen_fd;//被动连接监听套接字
	int data_process;//当前是否处于数据传输状态
	//限速
	long bw_transfer_start_sec;//开始传输时间的秒数
	long bw_transfer_start_usec;//开始传输的微秒数
    unsigned int bw_upload_rate_max;//上传最大速率
    unsigned int bw_download_rate_max;
	//父子进程通道
	int parent_fd;
	int child_fd;
	//FTP协议状态
	int is_ascii;//ascii模式为 1
    long long restart_pos;//用于断点续传，保存断点位置
    char *rnfr_name;//保存文件名称用于重命名
    int abor_received;///表明收到ABOR命令
    ///连接数限制
    unsigned int num_clients;///客户端数量
    unsigned int num_this_ip;///当前IP连接数
}session_t;
void begin_session(session_t* sess);


#endif
