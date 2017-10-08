//进行协议解析的模块。主要进行数据传输，进行ftp通信细节的处理
#include "ftpproto.h"
#include "sysutil.h"
#include"str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"
#include "session.h"
void ftp_reply(session_t *sess,int status,const char* text);
void ftp_lreply(session_t *sess,int status,const char* text);
int get_port_fd(session_t* sess);
int get_pasv_fd(session_t *sess);
void handle_alarm_timeout(int sig);
void start_cmdio_alarm(void);
void start_data_alarm(void);

void check_abor(session_t * sess);
void handle_sigurg(int sig);
//列出当前目录
int List_common(session_t *sess,int detail);
int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);
void up_load_common(session_t *sess,int is_append);
void limit_rate(session_t* sess,int bytes_transfered,int is_upload);
//名字符串与命令处理函数对应。用来解决if else太多的问题
static void do_user(session_t *sess);//处理客户端USER命令
static void do_pass(session_t *sess);//处理客户端PASS命令
static void do_cwd(session_t *sess);//改变工作目录
static void do_cdup(session_t *sess);//回到上一层目录
static void do_quit(session_t *sess);//退出
//带参命令处理函数
static void do_port(session_t *sess);//PORT命令处理。主动模式
static void do_pasv(session_t *sess);//PASV命令处理。被动模式
static void do_type(session_t *sess);//转换到ASCII码模式
//static void do_stru(session_t *sess);
//static void do_mode(session_t *sess);
//服务命令处理函数
static void do_retr(session_t *sess);//处理客户端下载文件，断点续传
static void do_stor(session_t *sess);//处理客户端上传文件
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);//短清单显示
static void do_rest(session_t *sess);//重置传输位置，客户端传过来断点位置。
static void do_abor(session_t *sess);///正常模式下收到ABOR命令
static void do_pwd(session_t *sess);//获取当前工作目录
static void do_mkd(session_t *sess);//创建文件夹
static void do_rmd(session_t *sess);//删除文件夹
static void do_dele(session_t *sess);//删除文件
static void do_rnfr(session_t *sess);//rnfr+需要重命名的文件
static void do_rnto(session_t *sess);//与rnfr配合使用，重命名文件
static void do_site(session_t *sess);
static void do_syst(session_t *sess);//返回系统信息
static void do_feat(session_t *sess);
static void do_size(session_t *sess);//获取文件大小
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);///防止服务器端空闲断开
static void do_help(session_t *sess);



typedef struct ftpcmd
{
    const char *cmd;
    void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

//命令名与函数映射关系结构体数组。NULL表示可以认识该命令，但未处理
static ftpcmd_t   ctrl_cmds[] = {
//访问控制命令
    {"USER",do_user},
    {"PASS",do_pass},
    {"CWD",do_cwd},//改变工作目录
    {"XCWD",do_cwd},
    {"CDUP",do_cdup},
    {"XCUP",do_cdup},
    {"QUIT",do_quit},
    {"ACCT",NULL},
    {"SMNT",NULL},
    {"REIN",NULL},
//传输参数命令
    {"PORT",do_port},
    {"PASV",do_pasv},
    {"TYPE",do_type},
    {"STRU",NULL},
    {"MODE",NULL},
//服务命令
    {"RETR",do_retr},
    {"STOR",do_stor},
    {"APPE",do_appe},
    {"LIST",do_list},//用数据连接传送目录列表
    {"NLST",do_nlst},//回显短目录清单
    {"REST",do_rest},
    {"ABOR",do_abor},
    {"\377\364\377\362ABOR",do_abor},
    {"PWD",do_pwd},
    {"XPWD",do_pwd},
    {"MKD",do_mkd},
    {"XMKD",do_mkd},//创建一个目录
    {"RMD",do_rmd},
    {"XRMD",do_rmd},
    {"DELE",do_dele},
    {"RNFR",do_rnfr},
    {"RNTO",do_rnto},
    {"SITE",do_site},
    {"SYST",do_syst},
    {"FEAT",do_feat},
    {"SIZE",do_size},
    {"STAT",do_stat},
    {"NOOP",do_noop},
    {"HELP",do_help},
    {"STOU",NULL},
    {"ALLO",NULL}

};
session_t *p_sess;
void handle_alarm_timeout(int sig)
{
    //关闭读端，要给客户端回应，不能close
    shutdown(p_sess->ctrl_fd,SHUT_RD);
    //发送一个回应
    ftp_reply(p_sess,FTP_IDLE_TIMEOUT,"Timeout.");
    //关闭写端
    shutdown(p_sess->ctrl_fd,SHUT_WR);
    exit(EXIT_FAILURE);
}
void start_cmdio_alarm(void)
{
    if(tunable_idle_session_timeout>0)
    {
        // 安装信号
        signal(SIGALRM,handle_alarm_timeout);
        //启动闹钟
        alarm(tunable_idle_session_timeout);
    }
}
//数据连接定时到时处理函数
void handle_sigalarm_timeout(int sig)
{   //数据连接超时并且没有数据传输
    if(!p_sess->data_process)
    {
        ftp_reply(p_sess,FTP_DATA_TIMEOUT,"Data timeout.Reconnect. sorry.");
        exit(EXIT_FAILURE);
    }
    //处于数据传输的状态收到了超时信号。我们将data_process=0 是它不处于数据传输的状态。重新安装信号
    else{
        p_sess->data_process=0;//在限速模块中设定
        start_data_alarm();
    }
}
//数据连接定时信号。 创建数据连接通道完成后开启该闹钟。
void start_data_alarm(void)
{
    if(tunable_data_connection_timeout>0)
    {
        // 安装信号
        signal(SIGALRM,handle_sigalarm_timeout);
        //启动闹钟
        alarm(tunable_idle_session_timeout);
    }
    else if(tunable_idle_session_timeout>0){ //没有开启数据连接超时
        alarm(0);//关闭控制连接的闹钟.防止数据传输过程中会话结束
    }
}
///产生这个信号，表明ABOR 命令来了，有紧急带外数据，我们需要接收ABOR
///登记ABOR命令已经接收，abor_received
void handle_sigurg(int sig)
{
    ///没有数据传输
    if(p_sess->data_fd==-1)
        return ;
        ///处于数据传输，接收数据ABOR
    char cmdline[MAX_COMMAND_LINE]={0};
    ///接收一行数据
    int ret=readline(p_sess->ctrl_fd,cmdline,MAX_COMMAND_LINE);
    if(ret<=0)
        ERR_EXIT("readline");
    ///去除\r\n
    str_trim_crlf(cmdline);
    if(strcmp(cmdline,"ABOR")==0||strcmp(cmdline,"\377\364\377\362ABOR")==0)
    {
        ///表示收到ABOR
         p_sess->abor_received=1;
         ///关闭数据连接状态
         shutdown(p_sess->data_fd,SHUT_RDWR);
    }
    else{
        ftp_reply(p_sess,FTP_BADCMD,"Unknown command.");
    }

}
//从客户端不停地接收数据，按行读取命令。
void handle_child(session_t* sess)
{
	//开始连接的欢迎信息
	//writen(sess->ctrl_fd,"220 (minftp 0.1)\r\n",strlen("220 (minftp 0.1)\r\n"));
	ftp_reply(sess,FTP_GREET,"(minftp 0.1)");
	int ret;
	while(1)
	{
		memset(sess->cmdline,0,sizeof(sess->cmdline));
		memset(sess->cmd,0,sizeof(sess->cmd));
		memset(sess->arg,0,sizeof(sess->arg));

		//启动一个闹钟,用于空闲断开
		start_cmdio_alarm();
		//读取客户端命令
		ret=readline(sess->ctrl_fd,sess->cmdline,MAX_COMMAND_LINE);
		//解析客户端ftp命令
		//处理命令，可能需要父进程，nobody进程的协助。每条指令之后\r\n
		if(ret==-1)
		{
			ERR_EXIT("readline");
		}
		else if(ret==0)//客户端关闭
		{
			ERR_EXIT(EXIT_SUCCESS);
		}

		//封装成模块函数处理字符串解析（字符串处理模块）
		//USER  jjl\r\n. %s中会有回车
		//printf("cmdline=[%s]\n",sess->cmdline);
		//去除\r\n
		str_trim_crlf(sess->cmdline);
		printf("cmdline=[%s]\n",sess->cmdline);
		//解析
		str_split(sess->cmdline,sess->cmd,sess->arg,' ');
		printf("cmd=[%s] arg=[%s]\n",sess->cmd,sess->arg);
		//将命令转换为大写
		str_upper(sess->cmd);
		//处理FTP命令。

	/*	//1、用户验证
		if(strcmp("USER",sess->cmd)==0)
		{
			do_user(sess);
		}
		//2、密码验证
		else if(strcmp("PASS",sess->cmd)==0)
		{
			do_pass(sess);
		}
	*/
		//ftp命令映射
		int i=0;
		int size=sizeof(ctrl_cmds)/sizeof(ctrl_cmds[0]);//结构体数组的长度
		 for(i=0;i<size;i++)
		{
			//找到了命令
			if(strcmp(ctrl_cmds[i].cmd,sess->cmd)==0)
			{

				//有处理函数
				if(ctrl_cmds[i].cmd_handler!=NULL)
				{
					ctrl_cmds[i].cmd_handler(sess);

				}
				else
				{
					ftp_reply(sess,FTP_COMMANDNOTIMPL,"Unimplement command.");//无处理函数
				}
				break;
			}

		}
		//没找到命令
		if(i==size)
		{
			ftp_reply(sess,FTP_BADCMD,"Unknown command.");
		}

	}

}
/*
typedef struct session
{
	//控制连接
	int ctrl_fd;//控制连接套接字
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	//父子进程通道
	int parent_fd;
	int child_fd;

}session_t;


#include <sys/types.h>
#include <pwd.h>
struct passwd *getpwnam(const char *name);
 struct passwd {
               char   *pw_name;
               char   *pw_passwd;
               uid_t   pw_uid;
               gid_t   pw_gid;
               char   *pw_gecos;
               char   *pw_dir;
               char   *pw_shell;
           };
*/
void ftp_reply(session_t* sess,int status,const char* text)
{
	char buf[1024]={0};
	sprintf(buf,"%d %s\r\n",status,text);
	writen(sess->ctrl_fd,buf,strlen(buf));
}

void ftp_lreply(session_t *sess,int status,const char* text)
{
	char buf[1024]={0};
	sprintf(buf,"%d-%s\r\n",status,text);
	writen(sess->ctrl_fd,buf,strlen(buf));
}
// struct dirent *readdir(DIR *dirp);
//int lstat(const char *pathname, struct stat *buf);
// size_t strftime(char *s, size_t max, const char *format,const struct tm *tm);
//  struct tm *localtime(const time_t *timep);//秒数转换为结构体
// ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);//获取符号链接的原文件

int List_common(session_t *sess,int detail)
{
	DIR* dir=opendir(".");
	if(dir==NULL)
		return 0;//打开当前目录失败
	struct dirent *dt;
	struct stat sbuf;
	while((dt=readdir(dir))!=NULL)
	{
		if(lstat(dt->d_name,&sbuf)<0)
		{
			continue;
		}
		//过滤'.'
		if(dt->d_name[0]=='.')
			continue;
        //list获取详细清单
         char buf[1024]={0};
        if(detail)
        {
                 //获取权限
            const char *perms=statbuf_get_perms(&sbuf);
            //连接数获取

            int off=0;
            off+=sprintf(buf,"%s",perms);//格式化到buf中。返回字符个数

            off+=sprintf(buf+off,"%3d   %-8d   %-8d",(int)sbuf.st_nlink,sbuf.st_uid,sbuf.st_gid);//连接数，用户ID 组ID

            off+=sprintf(buf+off,"%8lu ",(unsigned long)sbuf.st_size);//文件大小



            const char *datebuf=statbuf_get_date(&sbuf);
            off+=sprintf(buf+off,"%s ",datebuf);


            if(S_ISLNK(sbuf.st_mode))
            {
                char tmp[1024]={0};
                readlink(dt->d_name,tmp,sizeof(tmp));
                sprintf(buf+off,"%s -> %s\r\n",dt->d_name,tmp);//符号链接文件
            }
            else
                sprintf(buf+off,"%s\r\n",dt->d_name);//文件名
            //printf("%s",buf);//并不是打印到标准输出
        }
       else//获取短清单，nlst命令只回显文件目录名称
       {
            sprintf(buf,"%s\r\n",dt->d_name);
       }
		writen(sess->data_fd,buf,strlen(buf));
	}
	closedir(dir);
	return 1;
}

int port_active(session_t *sess)
{

	if(sess->port_addr)
	{

		if(pasv_active(sess))
		{
			fprintf(stderr,"both port and pasv are active.");
			exit(EXIT_FAILURE);
		}

		return 1;
	}
	return 0;
}




int pasv_active(session_t *sess)
{

/* //现在由nobody进程创建监听套接字，所以要请求nobody进程查看监听套接字是否创建成功
	if(sess->pasv_listen_fd!=-1)
	{

		if(port_active(sess))
		{
			fprintf(stderr,"both port and pasv are active.");
			exit(EXIT_FAILURE);
		}

		return 1;
	}
*/

    //请求nobody进程判定被动模式是否处于激活状态
    priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_PASV_ACTIV);
    //接收nobody进程的应答，激活为1，否则为0
    int active=priv_sock_get_int(sess->child_fd);
    if(active)
    {
        if(port_active(sess))
		{
			fprintf(stderr,"both port and pasv are active.");
			exit(EXIT_FAILURE);
		}

		return 1;
    }
	return 0;
}
//用于port模式下从nobody进程接收数据连接套接字
int get_port_fd(session_t* sess)
{

        //向nobody进程发起请请求
        priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_GET_DATA_SOCK);
        //将端口和IP发送给nobody
        unsigned short port=ntohs(sess->port_addr->sin_port);
        char *ip=inet_ntoa(sess->port_addr->sin_addr);
        priv_sock_send_int(sess->child_fd,(int)port);
        priv_sock_send_buf(sess->child_fd,ip,strlen(ip));

        //接收对方的应答，看数据连接套接字是否建立成功
        char res=priv_sock_get_result(sess->child_fd);
        if(res==PRIV_SOCK_RESULT_BAD)
        {

            return 0;
        }
        else if(res==PRIV_SOCK_RESULT_OK)
        {

            //成功应答，继续接收数据连接文件描述符
            sess->data_fd=priv_sock_recv_fd(sess->child_fd);
        }

    return 1;

}
int get_pasv_fd(session_t *sess)
{
    //向nobody进程请求被动模式数据连接套接字
    priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_PASV_ACCEPT);
    //接收Nobody应答
    char res=priv_sock_get_result(sess->child_fd);
    if(res==PRIV_SOCK_RESULT_BAD)
    {
        return 0;
    }
    else if(res==PRIV_SOCK_RESULT_OK)
    {
        sess->data_fd=priv_sock_recv_fd(sess->child_fd);
    }
    return 1;
}
//创建数据连接套接字
int get_transfer_fd(session_t *sess)
{

	//检测之前是否收到PORT或者PASV命令。收到的话会有do_port或者do_pasv.
	if(!port_active(sess)&&!pasv_active(sess))
	{
		ftp_reply(sess,FTP_BADSENDCONN ,"Use PORT or PASV first.");
		return 0;//两种模式都未被激活,需要给客户端应答，防止客户端阻塞
	}

    int ret=1;
	//如果是主动模式
	if(port_active(sess))
	{
		/*
		sock,bind,connect
		*/

/*
		//tcp_client(20);//返回数据套接字。数据连接的创建要用nobody进程来协助
		int fd=tcp_client(0);//用户登录进来以后。此时在wsw进程中，它无权进行端口的绑定。所以要nobody进程协助。
		//服务器端发起连接,超时时间由配置文件来配置，地址有do_port时保存
		if(connect_timeout(fd,sess->port_addr,tunable_connect_timeout)<0)
		{
			close(fd);
			return 0;
		}
		sess->data_fd=fd;
*/
    //已经将客户端发送过来的ip和端口解析出来了，下面利用nobody进程来连接客户端，创建数据连接套接字
	/*
	FTP服务进程接收PORT h1,h2,h3,h4,p1,p2
	解析IP和PORT
	向nobody发送一个整数port
	向nobody发送一个字符串ip
    */


       if(get_port_fd(sess)==0)//创建数据连接套接字失败
       {
           ret=0;
       }

	}


	//如果是被动模式
	if(pasv_active(sess))
	{
	    /*
		int conn=accept_timeout(sess->pasv_listen_fd,NULL,tunable_accept_timeout);

		close(sess->pasv_listen_fd);
		if(conn==-1)
		{
			return 0;
		}
		sess->data_fd=conn;//保存数据连接套接字
        */
        if(get_pasv_fd(sess)==0)
        {
            ret=0;
        }
	}

    if(sess->port_addr)//释放套接字地址内容
    {
        free(sess->port_addr);
        sess->port_addr=NULL;
    }
    if(ret)
    {
        //成功创建数据连接通道后，安装SIGALARM信号,并启动闹钟。设定超时断开
        start_data_alarm();
    }
	return ret;
}
/*

struct passwd *getpwuid(uid_t uid);

struct spwd *getspnam(const char *name);
 struct spwd {
               char *sp_namp;     // Login name
               char *sp_pwdp;     // Encrypted password  加密密码<>明文
               long  sp_lstchg;
               long  sp_min;
               long  sp_max;
               long  sp_warn;
               long  sp_inact;
               long  sp_expire;
               unsigned long sp_flag;
           };
//明文加密函数.需要在makefile中链接-lcrypt库
char *crypt(const char *key, const char *salt);
第一个参数是明文，第二个是种子。取Encrypted password，加密密码作为种子
*/
//用户名和密码是主机的用户名和密码
static void do_user(session_t *sess)
{
	//USER  wsw
	struct passwd*  pw;
	pw=getpwnam(sess->arg);
	if(pw==NULL)
	{
		//用户不存在
		ftp_reply(sess,FTP_LOGINERR,"1Login incorrect.");
		//writen(sess->ctrl_fd,"530 Login incorrect.\r\n",strlen("530 Login incorrect.\r\n"));
		return;
	}
	sess->uid=pw->pw_uid;
	ftp_reply(sess,FTP_GIVEPWORD,"Please specify the password.");
	//writen(sess->ctrl_fd,"331 Please specify the password.\r\n",strlen("331 Please specify the password.\r\n"));

}
static void do_pass(session_t *sess)
{

	struct passwd *pw=getpwuid(sess->uid);
	if(pw==NULL)
	{
		//用户不存在
		ftp_reply(sess,FTP_LOGINERR,"2Login incorrect.");
		return ;
	}
	struct spwd *sp=getspnam(pw->pw_name);
	if(sp==NULL)
	{
		//阴影文件不存在
		printf("name=[%s]\n",pw->pw_name);
		ftp_reply(sess,FTP_LOGINERR,"3Login incorrect.");
		return ;
	}
	//密码存放在影子文件中。现将明文加密，将加密结果与影子文件中的加密密码比较
	char *encrypted_pass=crypt(sess->arg,sp->sp_pwdp);
	if(strcmp(encrypted_pass,sp->sp_pwdp)!=0)
	{
		//密码不正确
		ftp_reply(sess,FTP_LOGINERR,"4Login incorrect.");
		return ;
	}

	///登陆成功之后开启可接受SIGURG信号，一旦接受到这个信号，进行处理，可以接收套接字带外数据
	signal(SIGURG,handle_sigurg);
	///开启进程接收SIGURG的能力
    activate_sigurg(sess->ctrl_fd);
    //修改umask值
    umask(tunable_local_umask);
	//设置服务进程为wsw用户进程，目录也要改到实际用户wsw家目录
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	chdir(pw->pw_dir);
	ftp_reply(sess,FTP_LOGINOK,"Login successful");
	//writen(sess->ctrl_fd,"230 Login successful.\r\n",strlen("230 Login successful.\r\n"));

}

/*应该是有一个miniftp 服务进程应该是wsw
wsw@unicorn-threads:~/Desktop/unp/miniftp_0812$ ps -ef| grep miniftp
root     105508 102498  0 20:02 pts/4    00:00:00 ./miniftp
nobody   105510 105508  0 20:02 pts/4    00:00:00 ./miniftp
root     105511 105510  0 20:02 pts/4    00:00:00 ./miniftp
wsw      105584 105563  0 20:03 pts/25   00:00:00 grep --color=auto miniftp
*/
/*改完以后
wsw@unicorn-threads:~/Desktop/unp/miniftp_0812$ ps -ef| grep miniftp
root     105642 102498  0 20:11 pts/4    00:00:00 ./miniftp
nobody   105643 105642  0 20:11 pts/4    00:00:00 ./miniftp
wsw      105644 105643  0 20:11 pts/4    00:00:00 ./miniftp      ftp服务进程
wsw      105646 105563  0 20:11 pts/25   00:00:00 grep --color=auto miniftp
*/

static void do_cwd(session_t *sess)
{
    //cwd  sh
    if(chdir(sess->arg)<0) //更改到arg路径下
    {
        //没有权限的话返回失败应答
         ftp_reply(sess, FTP_FILFAIL ,"Failed to change directory.");
         return;
    }
    ftp_reply(sess,FTP_CWD_OK ,"Directory successfully changed.");
	return;
}
static void do_cdup(session_t *sess)
{
    //cdup 相当于 cd ..
     if(chdir("..")<0) //更改到arg路径下
    {
        //没有权限的话返回失败应答
         ftp_reply(sess, FTP_FILFAIL ,"Failed to change directory.");
         return;
    }
    ftp_reply(sess,FTP_CWD_OK ,"Directory successfully changed.");
	return;
	return ;
}
static void do_quit(session_t *sess)
{
    ftp_reply(sess,FTP_GOODBYE,"GOODBYE");
    exit(EXIT_SUCCESS);

}
//主动模式，发送客户端IP和端口，服务器端去连接客户端
static void do_port(session_t *sess)
{
	//223,3,38,48,194,139.保存IP和端口
	unsigned int v[6];
	sscanf(sess->arg,"%u,%u,%u,%u,%u,%u",&v[2],&v[3],&v[4],&v[5],&v[0],&v[1]);//2 3 4 5 存放IP。0是高八位，1是低八位
	sess->port_addr=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr,0,sizeof(struct sockaddr_in));
	sess->port_addr->sin_family=AF_INET;
	unsigned char* p=(unsigned char*)&sess->port_addr->sin_port;//要取地址
	p[0]=v[0];
	p[1]=v[1];

	p=(unsigned char*)&sess->port_addr->sin_addr;
	p[0]=v[2];
	p[1]=v[3];
	p[2]=v[4];
	p[3]=v[5];

	ftp_reply(sess,FTP_PORTOK,"PORT command successful. Consider using PASV.");

}

//被动模式。将服务器IP 与 端口号发给客户端，以便客户端连接
static void do_pasv(session_t *sess)
{

	//Entering Passive Mode (服务器ip和已连接端口号发送给客户端)
	char ip[16];
	getlocalip(ip);

/*
//改由nobody进程来完成绑定端口并回传。并且在do_lsit时建立数据连接通道也由nobody进程完成
	sess->pasv_listen_fd=tcp_server(ip,0);//绑定临时端口，返回监听套接字保存到被动连接监听套接字变量中
	struct sockaddr_in addr;
	socklen_t addrlen=sizeof(addr);
	if(getsockname(sess->pasv_listen_fd,(struct sockaddr *)&addr,&addrlen)<0)
	{
		ERR_EXIT("getsockname");
	}
	unsigned port=ntohs(addr.sin_port);//获取临时端口号
*/
    //请求nobody协助完成监听套接字创建
   priv_sock_send_cmd(sess->child_fd,PRIV_SOCK_PASV_LISTEN);
    //接收端口号
   unsigned short port=(int)priv_sock_get_int(sess->child_fd);

	unsigned int v[4];
        sscanf(ip,"%u.%u.%u.%u",&v[0],&v[1],&v[2],&v[3]);
	char text[1024]={0};
	sprintf(text,"Entering Passive Mode (%u,%u,%u,%u,%u,%u)",v[0],v[1],v[2],v[3],port>>8,port&0xFF);//高8位，低8位
	ftp_reply(sess,FTP_PASVOK,text);
}


static void do_type(session_t *sess)
{
	if(strcmp(sess->arg,"A")==0)
	{
		sess->is_ascii=1;
		ftp_reply(sess,FTP_TYPEOK,"Switching to ASCII mode.");
	}
	else if(strcmp(sess->arg,"I")==0)
	{
		sess->is_ascii=0;
		ftp_reply(sess,FTP_TYPEOK,"Switching to Binary mode.");
	}
	else
	     ftp_reply(sess,FTP_BADCMD,"Unrecognised TYPE command.");
}

/*
static void do_stru(session_t *sess)
{

}
static void do_mode(session_t *sess)
{

}
*/
//限速处理
void limit_rate(session_t* sess,int bytes_transfered,int is_upload)
{
    //在限速模块中设定数据传输状态
    sess->data_process=1;
    ////睡眠时间=（当前传输速度/最大传输速度-1）*当前传输时间
    long curr_sec=get_time_sec();
    long curr_usec=get_time_sec();
    //传输时间
    double elapsed;
    elapsed=(double)(curr_sec-sess->bw_transfer_start_sec);
    elapsed+=(double)(curr_usec-sess->bw_transfer_start_usec)/(double)1000000;

    if(elapsed<=(double)0)
    {
        elapsed=(double)0.01;
    }
    //当前传输速度.每秒的字节数
    unsigned int bw_rate=(unsigned int)((double)bytes_transfered/elapsed);
    //当前传输速度/最大限速。得到速度比.
    double rate_ratio;
    if(is_upload)
    {
        if((double)bw_rate<=sess->bw_upload_rate_max)
        {
            sess->bw_transfer_start_sec=curr_sec;
            sess->bw_transfer_start_usec=curr_usec;
            return;//不用限速
        }
        rate_ratio=(double)bw_rate/sess->bw_upload_rate_max;
    }
    else
    {
         if((double)bw_rate<=sess->bw_download_rate_max)
        {
            sess->bw_transfer_start_sec=curr_sec;
            sess->bw_transfer_start_usec=curr_usec;
            return;//不用限速
        }
        rate_ratio=(double)bw_rate/sess->bw_download_rate_max;
    }

    //求出睡眠时间
    double  pause_time;
    pause_time=elapsed*(rate_ratio-(double)1);
    //利用nanosleep函数进行睡眠
    //int nanosleep(const struct timespec *req, struct timespec *rem);
    /*
     struct timespec {
               time_t tv_sec;
               long   tv_nsec;
           };
    */
    nano_sleep(pause_time);
    //睡眠结束要把下载开始时间重置
    sess->bw_transfer_start_sec=get_time_sec();
    sess->bw_transfer_start_usec=get_time_usec();
}

//用于客户下载
static void do_retr(session_t *sess)
{


    //下载文件、断点续载

    //创建数据连接
	if(get_transfer_fd(sess)==0)//成功1.失败0
		return ;

    //获取断点位置并且恢复为0
    long long offset=sess->restart_pos;
    sess->restart_pos=0;
    //打开文件  客户端命令 ： RETR  /home/jjl/tmp/echocli.c
    int fd=open(sess->arg,O_RDONLY);
    if(fd==-1)
    {
        ftp_reply(sess,FTP_FILFAIL,"Failed to open file.");
        return ;
    }

    //加读锁。封装一个加读锁防止其他进程写文件
    int ret;
    ret=lock_file_read(fd);//成功加锁返回1.失败返回0
    if(ret<0)
    {
        ftp_reply(sess,FTP_FILFAIL,"Failed to lock file");
        return ;
    }
    //判断是否是普通文件，设备文件不能被下载
    struct stat sbuf;
    ret=fstat(fd,&sbuf);
    if(!S_ISREG(sbuf.st_mode))
    {
        ftp_reply(sess,FTP_FILFAIL,"Failed to open the file");
        return ;
    }

    if(offset!=0)
    {
        //lseek设置下一次读的初始位置
        ret=lseek(fd,offset,SEEK_SET);
        if(ret==-1)
        {
            ftp_reply(sess,FTP_FILFAIL,"Failed to open the file");
            return ;
        }
    }
	//响应：150 Opening BINARY mode data connection for  /home/jjl/tmp/echocli.c  (1085 bytes)
	char text[1024]={0};
	//二进制模式和ASCII模式.区别在于是否对/r/n处理
	if(sess->is_ascii)
    {
        sprintf(text,"Opening ASCII mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
    }
    else
    {
        sprintf(text,"Opening Binary mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
    }
	ftp_reply(sess,FTP_DATACONN,"Here comes the directory listing");
	//下载文件(二进制)
	/* read方法效率不是很高，内核和用户态互相切换
	char buf[4096]={0};
	int flag=0;//区分错误类型
	while(1)
    {
        ret=read(fd,buf,sizeof(buf));
        if(ret==-1)
        {
            if(errno==EINTR)
                continue;
            else{
                     flag=1;
                     break;
                }
        }
        else if(ret==0)//读到结束.EOF
        {
            flag=0;
            break;
        }
        if(writen(sess->data_fd,buf,ret)!=ret)
        {
                 flag=2;
                 break;
        }

    }
    */
    //利用sendfile实现文件下载传输效率较高
    //  ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
    long long bytes_to_send=sbuf.st_size;//实际要发送的数据大小
    int flag=0;
    if(offset>bytes_to_send)
    {
        bytes_to_send=0;
    }
    else
    {
        bytes_to_send-=offset;
    }
    sess->bw_transfer_start_sec=get_time_sec();
    sess->bw_transfer_start_usec=get_time_usec();
    while(bytes_to_send)
    {
        int num_this_time=bytes_to_send>4096?4096:bytes_to_send;
        ret=sendfile(sess->data_fd,fd,NULL,num_this_time);//在内核中完成不用处理信号中断问题,也不用缓冲区帮助
        if(ret==-1)
        {
            flag=2;
            break;
        }
    ///睡眠限速
        limit_rate(sess,ret,0);
        ///abor应答
        if(sess->abor_received)
        {
            flag=2;
            break;
        }
        bytes_to_send-=ret;
    }
    if(bytes_to_send==0)
    {
        flag=0;
    }
	///关闭数据连接套接字.不关闭的话，内容显示不出来。没有关闭客户端无法判定是否结束接收
	close(sess->data_fd);
	sess->data_fd=-1;
	close(fd);//关闭文件
	///给客户端响应,防止abor在传输刚结束过来，应答两次226
	if(flag==0&&!sess->abor_received)
        ftp_reply(sess,FTP_TRANSFEROK,"Transfer complete.");
    else if(flag==1)
        ftp_reply(sess,FTP_BADSENDFILE ,"Failure reading from local file.");
    else if(flag==2)
        ftp_reply(sess,FTP_BADSENDNET ,"Failure writing to network stream.");
    check_abor(sess);
    ///重新开启控制连接闹钟
    start_cmdio_alarm();
}
///检查abor命令有没有过来
void check_abor(session_t* sess)
{
    if(sess->abor_received)
    {
        sess->abor_received=0;
        ftp_reply(sess,FTP_ABOROK ,"ABOR successful");
    }
}
//用于客户上传文件 两种上传方式1：普通上传  2：REST+STOR  3：APPE
void up_load_common(session_t *sess,int is_append)
{


    //创建数据连接通道
    if(get_transfer_fd(sess)==0)
    {
        return;
    }
    long long offset=sess->restart_pos;
    sess->restart_pos=0;
    //打开文件.创建从客户接收到的待上传文件。文件名为接收到的参数
    int fd=open(sess->arg,O_CREAT|O_WRONLY,0666);
    if(fd==-1)
    {
        ftp_reply(sess,FTP_UPLOADFAIL,"Could not create file.");
        return;
    }

    int ret;
    //加写锁。上传文件的时候，防止其他任何进程读或者写该文件
    ret=lock_file_write(fd);
    if(ret==-1)
    {
        ftp_reply(sess,FTP_UPLOADFAIL,"Could not create file.");
        return ;
    }
    //STOR 普通上传
    if(!is_append&&offset==0)//STOR
    {
        //先清空文件
        ftruncate(fd,0);
        if(lseek(fd,0,SEEK_SET)<0)
        {
             ftp_reply(sess,FTP_UPLOADFAIL,"Could not create file.");
             return ;
        }
    }
    else if(!is_append&&offset!=0) //REST+STOT
    {
        if(lseek(fd,offset,SEEK_SET)<0)
        {
             ftp_reply(sess,FTP_UPLOADFAIL,"Could not create file.");
             return ;
        }
    }
    else if(is_append)
    {
        //追加
        if(lseek(fd,0,SEEK_END)<0)
        {
             ftp_reply(sess,FTP_UPLOADFAIL,"Could not create file.");
             return ;
        }
    }
    struct stat sbuf;
    ret=fstat(fd,&sbuf);
    if(!S_ISREG(sbuf.st_mode))
    {
        ftp_reply(sess,FTP_UPLOADFAIL,"Could not create file.");
        return ;
    }
    //150信息
    //响应：150 Opening BINARY mode data connection for  /home/jjl/tmp/echocli.c  (1085 bytes)
	char text[1024]={0};
	//二进制模式和ASCII模式.区别在于是否对/r/n处理
	if(sess->is_ascii)
    {
        sprintf(text,"Opening ASCII mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
    }
    else
    {
        sprintf(text,"Opening Binary mode data connection for %s (%lld bytes).",sess->arg,(long long)sbuf.st_size);
    }
	ftp_reply(sess,FTP_DATACONN,"Here comes the directory listing");

	//上传文件
	int flag=0;
	char buf[1024];
/*
	//上传数据之前，重新安装SIGALARM信号,并启动闹钟
	start_data_alarm();
*/
	//睡眠时间=（当前传输速度/最大传输速度-1）*当前传输时间
    //开始传输的时间
    sess->bw_transfer_start_sec=get_time_sec();//获取当前秒数
    sess->bw_transfer_start_usec=get_time_usec();//获取当前微秒数

	while(1)
    {
        ret=read(sess->data_fd,buf,sizeof(buf));//从数据连接套接字接收数据然后写入打开的文件中实现上传
        if(ret==-1)
        {
            if(errno==EINTR)
                continue;
            else{
                     flag=2;
                     break;
                }
        }
        else if(ret==0)//读到结束.EOF
        {
            flag=0;
            break;
        }

        limit_rate(sess,ret,1);//读取到的字节数
        ///如果处于睡眠限速，不能知道是否有abpr,所以限速结束判断是否收到ABOR
        ///数据传输未完毕
        if(sess->abor_received)
        {
            flag=2;///跳出给客户426应答
            break;
        }
        if(writen(fd,buf,ret)!=ret)//写入到本地打开的文件中
        {
                 flag=1;
                 break;
        }
    }
    ///关闭数据连接套接字
    close(sess->data_fd);
	sess->data_fd=-1;
	close(fd);//关闭文件
	///给客户端响应
	if(flag==0)
        ftp_reply(sess,FTP_TRANSFEROK,"Transfer complete.");
    else if(flag==1)
        ftp_reply(sess,FTP_BADSENDFILE ,"Failure writing to  local file.");
    else if(flag==2)
        ftp_reply(sess,FTP_BADSENDNET ,"Failure reading from network stream.");

    ///如果传输完成了，有ABOR命令过来了，再给客户端226应答
    check_abor(sess);
    ///数据传输完，重新开启控制连接的闹钟.可能数据传输时将其关闭了。
    start_cmdio_alarm();

}

//上传文件。
static void do_stor(session_t *sess)
{
    up_load_common(sess,0);
}
static void do_appe(session_t *sess)
{
    up_load_common(sess,1);
}


static void do_list(session_t *sess)
{

	//创建数据连接
	if(get_transfer_fd(sess)==0)//成功1.失败0
		return ;

	//响应150
	ftp_reply(sess,FTP_DATACONN,"Here comes the directory listing");
	//传输列表,0表示短清单，1表示详细清单
	List_common(sess,1);
	//关闭数据连接套接字.不关闭的话，内容显示不出来。没有关闭客户端无法判定是否结束接收
	close(sess->data_fd);
	sess->data_fd=-1;
	//给客户端226响应
	ftp_reply(sess,FTP_TRANSFEROK,"Directory send OK");
}

//短清单显示
static void do_nlst(session_t *sess)
{
    //创建数据连接
	if(get_transfer_fd(sess)==0)//成功1.失败0
		return ;

	//响应150
	ftp_reply(sess,FTP_DATACONN,"Here comes the directory listing");
	//传输列表，0表示短清单，1表示详细清单
	List_common(sess,0);
	//关闭数据连接套接字.不关闭的话，内容显示不出来。没有关闭客户端无法判定是否结束接收
	close(sess->data_fd);
	sess->data_fd=-1;
	//给客户端226响应
	ftp_reply(sess,FTP_TRANSFEROK,"Directory send OK");
}
//保存客户端断点位置
static void do_rest(session_t *sess)
{
    sess->restart_pos=str_to_longlong(sess->arg);
    char text[1024]={0};
    sprintf(text,"Restart position accepted (%lld).",sess->restart_pos);
    ftp_reply(sess,FTP_RESTOK,text);
}
///正常收到abor
static void do_abor(session_t *sess)
{
    ftp_reply(sess,FTP_ABOR_NOCONN,"NO Transfer to ABOR");
}



//将当前工作目录的绝对路径复制到参数buffer所指的内存空间中,参数maxlen为buffer的空间大小。
//  char *getcwd(char *buf, size_t size);

static void do_pwd(session_t *sess)
{
	char text[1024]={0};
	char dir[1024+1]={0};
	getcwd(dir,1024);
	sprintf(text,"\"%s\"",dir);
	ftp_reply(sess,FTP_PWDOK,text);
}


//创建目录
static void do_mkd(session_t *sess)
{
    //实际权限为 0777&umask, umask可以在配置文件中配置
    if(mkdir(sess->arg,0777)<0)
    {
        //如果文件夹没有写的权限，则不能在里面创建文件夹，必须进行错误应答
        ftp_reply(sess,FTP_FILFAIL,"Created directory operation failed.");
        return;
    }
    char text[4096]={0};
    //判定是否为绝对路径
    if(sess->arg[0]=='/')
    {
        sprintf(text,"%s created",sess->arg);
    }
    else
    {
        char dir[4096+1]={0};
        //获取当前路径
        getcwd(dir,4096);
        if(dir[strlen(dir)-1]=='/')
        {
            sprintf(text ,"%s%s created",dir,sess->arg);//当前路径加上相对路径
        }
        else
            sprintf(text,"%s/%s created",dir,sess->arg);
    }
    ftp_reply(sess,FTP_MKDIROK,text);
}
//删除文件夹
static void do_rmd(session_t *sess)
{
    if(rmdir(sess->arg)<0)
    {
       ftp_reply(sess,FTP_FILFAIL,"Remove directory operation failed.");
        return;
    }
     ftp_reply(sess,FTP_RMDIROK,"Remove directory operation successful.");
    return ;
}
//DELE  /......  删除文件
static void do_dele(session_t *sess)
{
    if(unlink(sess->arg)<0)
    {
        ftp_reply(sess,FTP_FILFAIL,"Delete operation failed.");
        return;
    }
    ftp_reply(sess,FTP_DELEOK,"Delete operation successful.");
    return ;
}
//获取文件名称用于重命名
static void do_rnfr(session_t *sess)
{
    sess->rnfr_name=(char*)malloc(strlen(sess->arg)+1);
    memset(sess->rnfr_name,0,strlen(sess->arg)+1);
    strcpy(sess->rnfr_name,sess->arg);
    ftp_reply(sess,FTP_RNFROK,"Ready for RNTO");
}
//对文件进行重命名.rename函数  int rename(const char *oldpath, const char *newpath);
static void do_rnto(session_t *sess)
{
    if(sess->rnfr_name==NULL)
    {
        ftp_reply(sess,FTP_NEEDRNFR,"RNFR required first");
        return ;
    }

    rename(sess->rnfr_name,sess->arg);
    ftp_reply(sess,FTP_RENAMEOK,"Rename successful");
    //释放内存并置空
    free(sess->rnfr_name);
    sess->rnfr_name=NULL;
}

static void do_site(session_t *sess)
{
    return ;
}
//返回系统信息
static void do_syst(session_t *sess)
{
	ftp_reply(sess,FTP_SYSTOK,"UNIX Type: L8");
}
//服务器特性
static void do_feat(session_t *sess)
{
	ftp_lreply(sess,FTP_FEAT,"Features: ");
	writen(sess->ctrl_fd," EPRT\r\n",strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd," EPSV\r\n",strlen(" EPSV\r\n"));
	writen(sess->ctrl_fd," MDTM\r\n",strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd," PASV\r\n",strlen(" PASV\r\n"));
	writen(sess->ctrl_fd," REST STREAM\r\n",strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd," SIZE\r\n",strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd," TVFS\r\n",strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd," UTF8\r\n",strlen(" UTF8\r\n"));
	ftp_reply(sess,FTP_FEAT,"END");
}
//获取文件大小.  size   jjl
static void do_size(session_t *sess)
{
    struct stat buf;
    if(stat(sess->arg,&buf)<0)
    {
        ftp_reply(sess,FTP_FILFAIL,"Size operation failed.");
        return;
    }
    //判断是否为普通文件.不能获取文件夹啥的大小
    if(!S_ISREG(buf.st_mode))
    {
         ftp_reply(sess,FTP_FILFAIL,"Could not get file size");
         return;
    }

    char text[1024]={0};
    sprintf(text,"%lld",(long long)buf.st_size);
    ftp_reply(sess,FTP_SIZEOK,text);
}
static void do_stat(session_t *sess)
{
    return ;
}
///接收客户端NOOP 命令，就会重新计时，防止服务器空闲断开
static void do_noop(session_t *sess)
{
    ftp_reply(sess,FTP_NOOPOK,"NOOP OK");
}
static void do_help(session_t *sess)
{
    ftp_lreply(sess,FTP_HELP,"The following commands are recognized.");
    writen(sess->ctrl_fd,"ABOR ACCT ALLO APPE CDUP CWD DELE EPRT EPSU TEAT HELP LIST MDTM\r\n ",
           strlen("ABOR ACCT ALLO APPE CDUP CWD DELE EPRT EPSU TEAT HELP LIST MDTM\r\n "));
    ftp_reply(sess,FTP_HELP,"Help OK");
	return ;
}













