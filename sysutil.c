#include "sysutil.h"

int tcp_client(unsigned short port)
{
	int sock;
	if((sock=socket(PF_INET,SOCK_STREAM,0))<0)
		ERR_EXIT("tcp_client");
	//通常port=0，客户端不需要绑定
	if(port>0)
	{

		int on=1;
		if((setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(const char*)(&on),sizeof(on)))<0)
			ERR_EXIT("setsockopt");

		struct sockaddr_in localaddr;
		char ip[16];
		getlocalip(ip);//下面有封装

        //char *ip;
        //ip="223.3.53.4";
		memset(&localaddr,0,sizeof(localaddr));
		localaddr.sin_family=AF_INET;
		localaddr.sin_port=htons(port);
		localaddr.sin_addr.s_addr=inet_addr(ip);//返回32位网络字节序地址
		if(bind(sock,(struct sockaddr*)&localaddr,sizeof(localaddr))<0)
			ERR_EXIT("bind");
	}
	return sock;
}
/**
tcp_server 用来启动tcp服务器
@host:服务器主机地址或者服务器主机名
@port:服务器端口号
@return:成功返回监听套接字
**/
int tcp_server(const char *host, unsigned short port)
{

	int listenfd;
	if((listenfd=socket(PF_INET,SOCK_STREAM,0))<0)
		ERR_EXIT("tcp_server");
	struct sockaddr_in servaddr;
	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	if(host!=NULL){
		if(inet_aton(host,&servaddr.sin_addr)==0)//不是IP地址
		{
			struct hostent* hp;
			hp=gethostbyname(host);
			if(hp==NULL)
				ERR_EXIT("gethostbyname");
			servaddr.sin_addr=*(struct in_addr*)hp->h_addr;
		}
	}
	else
		servaddr.sin_addr.s_addr=htonl(INADDR_ANY);

	servaddr.sin_port=htons(port);

	int on=1;
	if((setsockopt(listenfd,SOL_SOCKET,SO_REUSEADDR,(const char*)(&on),sizeof(on)))<0)
		ERR_EXIT("setsockopt");
	if(bind(listenfd,(struct sockaddr*)&servaddr,sizeof(servaddr))<0)
		ERR_EXIT("bind");
	if(listen(listenfd,SOMAXCONN)<0)
		ERR_EXIT("listen");
	return listenfd;
}

//获取本机IP。
int getlocalip(char * ip)
{
	char host[100]={0};
	if(gethostname(host,sizeof(host))<0)
		return -1;
	struct hostent *hp;
	if((hp=gethostbyname(host))==NULL)
		return -1;
	strcpy(ip,inet_ntoa(*(struct in_addr*)hp->h_addr));
		return 0;
}


//将套接口设置为非阻塞模式，防止直接调用connect阻塞
void activate_nonblock(int fd)
{
	int ret;
	int flags=fcntl(fd,F_GETFL);
	if(flags==-1)
		ERR_EXIT("fcntl error");
	flags|=O_NONBLOCK;//添加非阻塞模式
	ret=fcntl(fd,F_SETFL,flags);
	if(ret==-1)
		ERR_EXIT("fcntl error");
}
//将套接口还原为阻塞模式
void deactivate_nonblock(int fd)
{
	int ret;
	int flags=fcntl(fd,F_GETFL);
	if(flags==-1)
		ERR_EXIT("fcntl");
	flags&=~O_NONBLOCK;
	ret=fcntl(fd,F_SETFL,flags);
	if(ret==-1)
		ERR_EXIT("fcntl");
}





int read_timeout(int fd,unsigned int wait_seconds)
{
	int ret=0;
	if(wait_seconds>0)
	{
		fd_set read_fdset;
		struct timeval timeout;
		FD_ZERO(&read_fdset);
		FD_SET(fd,&read_fdset);

		timeout.tv_sec=wait_seconds;
		timeout.tv_usec=0;
		do
		{
			ret=select(fd+1,&read_fdset,NULL,NULL,&timeout);
		}while(ret<0&&errno==EINTR);

		if(ret==0)//超时
		{
			ret=-1;
			errno=ETIMEDOUT;
		}
		else if(ret==1)//检测到一个事件
			ret=0;
	}

	return ret;//wait_seconds==0 直接返回
}

/*
写超时检测函数,不含写操作
成功未超时返回0，失败超时返回-1且errno=ETIMEDOUT
*/
int write_timeout(int fd,unsigned int wait_seconds)
{
	int ret=0;
	if(wait_seconds>0)
	{
		fd_set write_fdset;
		struct timeval timeout;
		FD_ZERO(&write_fdset);
		FD_SET(fd,&write_fdset);

		timeout.tv_sec=wait_seconds;
		timeout.tv_usec=0;
		do
		{
			ret=select(fd+1,NULL,&write_fdset,NULL,&timeout);
		}while(ret<0&&errno==EINTR);

		if(ret==0)//超时
		{
			ret=-1;
			errno=ETIMEDOUT;
		}
		else if(ret==1)//检测到一个事件
			ret=0;
	}

	return ret;//wait_seconds==0 直接返回
}

/*
accept_timeout 带超时的accept...select在如果是监听套接口(服务器)，已完成连接队列不为空时返回
fd:套接字
addr:输出参数,返回对方地址
wait_seconds:等待返回的秒数。如果为0表示正常模式
成功未超时返回已连接套接字，超时返回-1并且errno=ETIMEDOUT
 int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
*/
int accept_timeout(int fd,struct sockaddr_in * addr,unsigned int wait_seconds)
{
	int ret;
	socklen_t addrlen=sizeof(struct sockaddr_in);
	if(wait_seconds>0)
	{
		fd_set accept_fdset;
		struct timeval timeout;
		FD_ZERO(&accept_fdset);
		FD_SET(fd,&accept_fdset);
		timeout.tv_sec=wait_seconds;
		timeout.tv_usec=0;
		do
		{
			ret=select(fd+1,&accept_fdset,NULL,NULL,&timeout);
		}while(ret==-1&&errno==EINTR);

		if(ret==-1)
			return -1;
		else if(ret==0)
		{
			errno=ETIMEDOUT;
			return -1;
		}
	}
	if(addr!=NULL)
		ret=accept(fd,(struct sockaddr *)addr,&addrlen);
	else
		ret=accept(fd,NULL,NULL);
	if(ret==-1)
		ERR_EXIT("accept error");
	return ret;
}

/**
*connect:建立三次握手时connect在服务器返回确认时就返回了。设定自己的连接超时时间。
*fd:套接字
*addr:要连接的对端服务器地址
*wait_seconds:等待超时秒数，如果为0表示正常模式
*成功(未超时)返回0，失败超时返回-1，并且errno=ETIMEDOUT
**/
int connect_timeout(int fd,struct sockaddr_in * addr,unsigned int wait_seconds)
{
	int ret;
	socklen_t addrlen=sizeof(struct sockaddr_in);
	if(wait_seconds>0)
		activate_nonblock(fd);//将套接口设置为非阻塞
	ret=connect(fd,(struct sockaddr *)addr,addrlen);//已经将套接口设置为非阻塞了，如果不能够立即连接成功，则返回EINPROGRESS错误。
	if(ret<0&&errno==EINPROGRESS)//连接正在处理。处理超时
	{
		fd_set connect_fdset;
		struct timeval timeout;
		FD_ZERO(&connect_fdset);
		FD_SET(fd,&connect_fdset);
		timeout.tv_sec=wait_seconds;
		timeout.tv_usec=0;
		do
		{
			//一旦connect建立连接，套接口就可以写了。
			ret=select(fd+1,NULL,&connect_fdset,NULL,&timeout);

		}while(ret<0&&errno==EINTR);
		if(ret==0)
		{
			ret=-1;
			errno=ETIMEDOUT;
		}
		else if(ret<0)
		{
			return -1;
		}
		else if(ret==1)
		{
			/*ret返回1，可能有两种情况。一种是fd有事件发生，connect建立连接可写了。
			*另一种情况是套接字本身产生错误.套接口上发生一个错误待处理，错误可以通过getsockopt指定SO_ERROR选项来获取
			*但是select函数没有出错，所以错误信息不能保存到errno
			*变量中。只有通过getsockopt来获取套接口fd的错误。
			*/
			int err;
			socklen_t socklen=sizeof(err);
			int sockoptret=getsockopt(fd,SOL_SOCKET,SO_ERROR,&err,&socklen);//成功返回0，错误返回-1
			if(sockoptret==-1)
			{
				return -1;
			}
			if(err==0)//套接字没有错误
				ret=0;//返回0成功未超时
			else//产生错误
			{
				errno=err;//套接字错误代码
				ret=-1;
			}
		}

	}
	if(wait_seconds>0)
	{
		deactivate_nonblock(fd);//重置为阻塞
	}
	return ret;
}


ssize_t readn(int fd,void *buf,size_t count)
{
	size_t nleft=count;
	ssize_t nread;
	char *bufp=(char*)buf;
	while(nleft>0)
	{
		if((nread=read(fd,bufp,nleft))<0)
		{
			if(errno==EINTR)
				continue;
			else
				return -1;
		}
		else if(nread==0)
			return (count-nleft);
		bufp+=nread;
		nleft-=nread;
	}
	return count;
}
ssize_t writen(int fd, const void *buf, size_t count)
{
	size_t nleft=count;
	ssize_t nwritten;
	char *bufp=(char*)buf;
	while(nleft>0)
	{
		if((nwritten=write(fd,bufp,nleft))<=0)
		{
			if(errno==EINTR)
				continue;
			return -1;
		}else if(nwritten==0)
			continue;
		bufp+=nwritten;
		nleft-=nwritten;
	}
	return count;

}
ssize_t recv_peek(int sockfd,void *buf,size_t len)
{
	while(1)
	{
		int ret=recv(sockfd,buf,len,MSG_PEEK);//从sockfd读取内容到buf,但不去清空sockfd,偷窥
		if(ret==-1&&errno==EINTR)
			continue;
		return ret;
	}
}
//偷窥方案实现readline避免一次读取一个字符
ssize_t readline(int sockfd,void * buf,size_t maxline)
{
	int ret;
	int nread;
	size_t nleft=maxline;
	char *bufp=(char*)buf;
	while(1)
	{
		ret=recv_peek(sockfd,bufp,nleft);//不清除sockfd,只是窥看
		if(ret<0)
			return ret;
		else if(ret==0)
			return ret;
		nread=ret;
		int i;
		for(i=0;i<nread;i++)
		{
			if(bufp[i]=='\n')
			{
				ret=readn(sockfd,bufp,i+1);//读出sockfd中的一行并且清空
				if(ret!=i+1)
					exit(EXIT_FAILURE);
				return ret;
			}
		}
		if(nread>nleft)
			exit(EXIT_FAILURE);
		nleft-=nread;
		ret=readn(sockfd,bufp,nread);
		if(ret!=nread)
			exit(EXIT_FAILURE);
		bufp+=nread;//移动指针继续窥看
	}
	return -1;
}





//通过套接字sock_fd发送文件描述字send_fd
void send_fd(int sock_fd,int send_fd)
{
	int ret;
	struct msghdr msg;//传递消息结构体
	struct cmsghdr * p_cmsg;//辅助数据结构体
	struct iovec vec;//数据发送缓冲区结构体
	char cmsgbuf[CMSG_SPACE(sizeof(send_fd))];//宏 获取辅助数据对象总大小（辅助数据空间大小）
	int *p_fds;
	char sendchar=0;
	//辅助信息
	//准备缓冲区并且指向它。空间已经算出来了
	msg.msg_control=cmsgbuf;
	msg.msg_controllen=sizeof(cmsgbuf);

	p_cmsg=CMSG_FIRSTHDR(&msg);

	p_cmsg->cmsg_level=SOL_SOCKET;//传递文件描述字
	p_cmsg->cmsg_type=SCM_RIGHTS;
	p_cmsg->cmsg_len=CMSG_LEN(sizeof(send_fd));
	//将send_fd放入控制信息的数据部分
	p_fds=(int *)CMSG_DATA(p_cmsg);
	*p_fds=send_fd;


	msg.msg_name=NULL;
	msg.msg_namelen=0;
	msg.msg_iov=&vec;
	msg.msg_iovlen=1;
	msg.msg_flags=0;

	//正常数据部分

	vec.iov_base=&sendchar;
	vec.iov_len=sizeof(sendchar);
	ret=sendmsg(sock_fd,&msg,0);
	if(ret!=1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd)
{
	int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char  cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	vec.iov_base=&recvchar;
	vec.iov_len=sizeof(recvchar);
	msg.msg_name=NULL;
	msg.msg_namelen=0;

	msg.msg_iov=&vec;
	msg.msg_iovlen=1;
	msg.msg_control=cmsgbuf;
	msg.msg_controllen=sizeof(cmsgbuf);
	msg.msg_flags=0;

	p_fd=(int *)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd=-1;
	//发送了一个字节，也接收一个
	ret=recvmsg(sock_fd,&msg,0);
	if(ret!=1)
		ERR_EXIT("recvmsg");

	p_cmsg=CMSG_FIRSTHDR(&msg);
	if(p_cmsg==NULL)
		ERR_EXIT("no passed fd");

	p_fd=(int *)CMSG_DATA(p_cmsg);
	recv_fd=*p_fd;
	if(recv_fd==-1)
		ERR_EXIT("no passed fd");

	return  recv_fd;
}
//获取文件权限

const  char *statbuf_get_perms(struct stat *sbuf)
{
        static char perms[]="----------";
		perms[0]='?';//文件类型
    	mode_t mode=sbuf->st_mode;
		switch (mode & S_IFMT)
		{
			case S_IFREG:
				perms[0]='-';
				break;
			case S_IFDIR:
				perms[0]='d';
				break;
			case S_IFLNK:
				perms[0]='l';
				break;
			case S_IFIFO:
				perms[0]='p';
				break;
			case S_IFSOCK:
				perms[0]='s';
				break;
			case S_IFCHR:
				perms[0]='c';
				break;
			case S_IFBLK:
				perms[0]='b';
				break;
			default:
				break;
		}

		if(mode & S_IRUSR)
		{
			perms[1]='r';
		}
		if(mode & S_IWUSR)
		{
			perms[2]='w';
		}
		if(mode & S_IXUSR)
		{
			perms[3]='x';
		}

		if(mode & S_IRGRP)
		{
			perms[4]='r';
		}
		if(mode & S_IWGRP)
		{
			perms[5]='w';
		}
		if(mode & S_IXGRP)
		{
			perms[6]='x';
		}

		if(mode & S_IROTH)
		{
			perms[7]='r';
		}
		if(mode & S_IWOTH)
		{
			perms[8]='w';
		}
		if(mode & S_IXOTH)
		{
			perms[9]='x';
		}
		//特殊权限位
		if(mode & S_ISUID)
		{
			perms[3]=(perms[3]=='x')?'s':'S';
		}
		if(mode & S_ISGID)
		{
			perms[6]=(perms[6]=='x')?'s':'S';
		}
		if(mode & S_ISVTX)
		{
			perms[9]=(perms[9]=='x')?'t':'T';
		}
    return perms;
}
//获取文件日期
const char* statbuf_get_date(struct stat *sbuf)
{
        //日期有两种格式
        static char datebuf[64]={0};
		const char* p_date_format="%b %e %H:%M";
		struct timeval tv;
		gettimeofday(&tv,NULL);//获取当前时间
		long local_time=tv.tv_sec;
		if(sbuf->st_mtime>local_time || (local_time-sbuf->st_mtime)>60*60*24*182) //修改时间超过半年
		{
			p_date_format="%b %e  %Y";//时间格式化
		}


		struct tm* p_tm=localtime(&local_time);
		strftime(datebuf,sizeof(datebuf),p_date_format,p_tm);//日期格式化到了datebuf中

        return datebuf;
}
//对文件加读锁,fcntl函数 int fcntl(int fd, int cmd, ... /* arg */ ); F_SETLKW
 /*锁的结构体
 struct flock {
               ...
               short l_type;     Type of lock: F_RDLCK,
                                   F_WRLCK, F_UNLCK
               short l_whence;   How to interpret l_start:
                                   SEEK_SET, SEEK_CUR, SEEK_END
               off_t l_start;    Starting offset for lock
               off_t l_len;      Number of bytes to lock
               pid_t l_pid;     PID of process blocking our lock
                                   (set by F_GETLK and F_OFD_GETLK)
               ...
           };
*/


int lock_internal(int fd,int lock_type)
{
    int ret;
    struct flock the_lock;
    memset(&the_lock,0,sizeof(the_lock));
    the_lock.l_type=lock_type;
    the_lock.l_whence=SEEK_SET;
    the_lock.l_start=0;
    the_lock.l_len=0;
    do
    {
        ret=fcntl(fd,F_SETLKW,&the_lock);
    } while(ret<0&&errno==EINTR);
    //ret<0上锁失败，是被信号中断的话则继续上锁，否则退出，等于0上锁成功。
    return ret;
}
//文件加读锁
int lock_file_read(int fd)
{
    return lock_internal(fd,F_RDLCK);

}
//文件加写锁
int lock_file_write(int fd)
{
    return lock_internal(fd,F_WRLCK);

}
//解锁文件
int unlock_file(int fd)
{
      int ret;
    struct flock the_lock;
    memset(&the_lock,0,sizeof(the_lock));
    the_lock.l_type=F_UNLCK;
    the_lock.l_whence=SEEK_SET;
    the_lock.l_start=0;
    the_lock.l_len=0;
    ret=fcntl(fd,F_SETLK,&the_lock);
    //ret<0解锁失败，是被信号中断的话则继续上锁，否则退出，等于0上锁成功。
    return ret;
}

static struct timeval s_curr_time;
long get_time_sec(void)
{
    if(gettimeofday(&s_curr_time,NULL)<0)
    {
        ERR_EXIT("gettimeofday");
    }
    return s_curr_time.tv_sec;
}
long get_time_usec(void)
{
    return s_curr_time.tv_usec;
}


//睡眠
//利用nanosleep函数进行睡眠
    //int nanosleep(const struct timespec *req, struct timespec *rem);
    /*
     struct timespec {
               time_t tv_sec;
               long   tv_nsec;
           };
    */
void nano_sleep(double seconds)
{
    int ret;
    time_t secs=(time_t)seconds;//整数部分
    double fractional=seconds-(double)secs;//小数部分
    struct timespec ts;
    ts.tv_sec=secs;
    ts.tv_nsec=(long)(fractional*(double)1000000000);
    do{
         ret=nanosleep(&ts,&ts);//第二个参数为剩余时间
    }while(ret==-1&&errno==EINTR);//信号打断

}
///开启套接字ctrl_fd接收带外数据功能
void  activate_oobinline(int fd)
{
    int oob_inline=1;///开启
    int ret;
    ///设置套接字选项
    ret=setsockopt(fd,SOL_SOCKET,SO_OOBINLINE,&oob_inline,sizeof(oob_inline));
    if(ret==-1)
    {
        ERR_EXIT("setsockopt");
    }
}
///在do_pass登录成功后开启该功能功能
///当文件描述符上有带外数据的时候，将产生SIGURG信号
///该函数设定当前进程能够接收fd文件描述符所产生的SIGURG信号
void activate_sigurg(int fd)
{
   int ret;
   ///开启当前进程可以接收某个文件描述符上的SIGURG信号
   ret=fcntl(fd,F_SETOWN,getpid());
   if(ret==-1)
    ERR_EXIT("Fcntl");
}






