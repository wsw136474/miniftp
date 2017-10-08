#include "sysutil.h"
#include "session.h"
#include "str.h"
#include "tunable.h"
#include "parseconf.h"
#include "common.h"
#include "ftpproto.h"
#include "ftpcodes.h"
#include "hash.h"
/*
typedef struct session
{
	//控制连接
	uid_t uid;
	int ctrl_fd;//控制连接套接字
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];
	//数据连接
	struct sockaddr* port_addr;//保存客户端发送的地址
	int data_fd;//数据连接套接字
	int pasv_listen_fd;
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
	int is_ascii;
	long long restart_pos;//用于断点续传，保存断点位置
    char *rnfr_name;
    int abor_received;
     ///连接数限制
    unsigned int num_clients;
    unsigned int num_this_ip;
}session_t;
*/
extern session_t *p_sess;
///当前子进程数目
static unsigned int s_children;
//判断连接数限制
void check_limits(session_t* sess);
void handle_sigchld(int sig);
///定义两个哈希表
static hash_t * s_ip_count_hash;//ip与连接数对应关系哈希表
static hash_t * s_pid_ip_hash;//进程号和ip对应关系的哈希表。父进程可以通过子进程退出时的进程号获取退出客户端的IP地址
///哈希函数
unsigned int hash_func(unsigned int buckets ,void* key);
unsigned int handle_ip_count(void* ip);///返回IP的连接数
void drop_ip_count(void *ip);
int main(void)
{
	/*测试str_all_space函数
	char *str1="	a b";
	char *str2="   		";
	if(str_all_space(str1))
		printf("str1 all space\n");
	else
		printf("str1 not all space\n");
	if(str_all_space(str2))
		printf("str2 all space\n");
	else
		printf("str2 not all space\n");


	测试str_upper函数
	//char *str3="abcdefG";//段错误 str3指向字符串常量，常量不能被修改。
	char str3[]="abcdefG";
	str_upper(str3);
	printf("str3=%s\n",str3);


	测试str_to_longlong函数
	long long result=str_to_longlong("12345678901234");
	printf("result=%lld\n",result);


	测试str_octal_to_uint函数
	int n=str_octal_to_uint("0711");
	printf("n=%d\n",n);
	*/

	//测试配置文件模块.读取配置文件
	parseconf_load_file(MINIFTP_CONF);
     ///服务器程序一般做成守护进程
    daemon(0,0);

	printf("tunable_pasv_enable=%d\n",tunable_pasv_enable);
	printf("tunable_port_enable=%d\n",tunable_port_enable);

	printf("tunable_listen_port=%u\n",tunable_listen_port);
	printf("tunable_max_clients=%u\n",tunable_max_clients);
	printf("tunable_max_per_ip=%u\n",tunable_max_per_ip);
	printf("tunable_accept_timeout=%u\n",tunable_accept_timeout);
	printf("tunable_connect_timeout=%u\n",tunable_connect_timeout);
	printf("tunable_idle_session_timeout=%u\n",tunable_idle_session_timeout);
	printf("tunable_data_connection_timeout=%u\n",tunable_data_connection_timeout);
	printf("tunable_local_umask=%o\n",tunable_local_umask);

	printf("tunable_upload_max_rate=%u\n",tunable_upload_max_rate);
	printf("tunable_download_max_rate=%u\n",tunable_download_max_rate);
	if(tunable_listen_address!=NULL)
		printf("tunable_listen_address=%s\n",tunable_listen_address);
	else
		printf("tunable_listen_address=NULL\n");
	//测试List_common函数
	//List_common();


	//判断启动用户
	if(getuid()!=0)
	{
		fprintf(stderr,"miniftp: must be started as root\n");
		exit(EXIT_FAILURE);
	}

	session_t sess=
	{
		/*控制连接*/
		0,-1,"","","",
		//数据连接
		NULL,-1,-1,0,
		//限速
		0,0,0,0,
		/*父子进程通道*/
		-1,-1,
		/* FTP协议状态 */
		0,0,NULL,0,
		/*连接数*/
		0,0
	};
	p_sess=&sess;
    //从配置文件中读取最大速率后保存到sess中
    sess.bw_download_rate_max=tunable_download_max_rate;
    sess.bw_upload_rate_max=tunable_upload_max_rate;
    ///创建哈希表
    s_ip_count_hash=hash_alloc(256,hash_func);///IP也是整数
    s_pid_ip_hash=hash_alloc(256,hash_func);///pid也是整数
	//处理服务进程的僵死问题.忽略///不忽视了，进行捕捉，将s_children变量值减1
	///子进程退出时，s_children变量要减1，但是子进程复制了父进程s_children，不改变父进程的值
	///所以我们在子进程退出处理信号时来处理
	signal(SIGCHLD,handle_sigchld);
	//多进程方式
	//开启ftp服务器监听
	int listenfd=tcp_server(tunable_listen_address,tunable_listen_port);
	int conn;
	pid_t pid;
	struct sockaddr_in addr;
	while(1)
	{

		//先不采用超时方式，对方地址填空
		conn=accept_timeout(listenfd,&addr,0);
		if(conn==-1)
			ERR_EXIT("accept_timeout");
        ///取出一个对方IP地址保存下来
        ///当一个客户登录的时候，要在s_ip_count_hash更新这个表中的对应项
        ///即该ip对应的连接数要加1，如果这个表项还不存在，要在表项中添加一条记录，并将对应的IP连接数加1
        unsigned int ip=addr.sin_addr.s_addr;
        sess.num_this_ip=handle_ip_count(&ip);///当前IP连接数
        ++s_children;
		pid=fork();
		//创建失败
		if(pid==-1)
        {
            	ERR_EXIT("fork");
            	--s_children;
        }
        sess.num_clients=s_children;
		if(pid==0)
		{
			close(listenfd);
			sess.ctrl_fd=conn;
			//判断连接数，子进程继承了变量
			check_limits(&sess);
			///不让信号继承,这样begin_session会话中，子进程退出时，nobody进程不会进行handsig信号的处理,不会对s_children--
			signal(SIGCHLD,SIG_DFL);
			//启动会话.
			begin_session(&sess);//要在root进程中才能调用影子文件。所以要root进程启动服务器
		}
		else
		{
		    hash_add_entry(s_pid_ip_hash,&pid,sizeof(pid),&ip,sizeof(unsigned int));
			close(conn);//回到开始，重新等待客户端
		}
	}
	return 0;
}

void check_limits(session_t* sess)
{
    ///先检查最大连接数限制
    if(tunable_max_clients>0&&sess->num_clients>tunable_max_clients)
    {
        ftp_reply(sess,FTP_TOO_MANY_USERS,"There are too many connected users,please try later.");
        exit(EXIT_FAILURE);///进程退出，向父进程发送信号
    }
    ///再检查每个IP连接数限制
    if(tunable_max_per_ip>0&&sess->num_this_ip>tunable_max_per_ip)
    {
        ftp_reply(sess,FTP_IP_LIMIT,"There are too many connected users,please try later.");
        exit(EXIT_FAILURE);///进程退出，向父进程发送信号
    }

}
///父进程获取退出进程
void handle_sigchld(int sig)
{
    ///当一个客户端退出时，那么该客户端对应的IP连接数要减1；
    ///处理过程是这样的，首先客户端退出时，父进程需要知道这个客户端的IP
    ///这个可以通过这个客户端的IP。这可以通过在s_pid_ip_hash查找的到
    ///得到了IP进而我们就可以在s_ip_count_hash表中找到了对应的连接数，进而可以减1
    pid_t pid;
    while((pid=waitpid(-1,NULL,WNOHANG))>0)//防止僵尸进程
    {
        --s_children;//父进程维护的子进程的数量
        unsigned int *ip=hash_lookup_entry(s_pid_ip_hash,&pid,sizeof(pid));
        if(ip==NULL)
        {
            continue;
        }
        ///对应IP连接数减一
        drop_ip_count(ip);
        ///进程退出了，对应的pid /ip表项也要移除了
        hash_free_entry(s_pid_ip_hash,&pid,sizeof(pid));
    }

}
///哈希函数
unsigned int hash_func(unsigned int buckets ,void* key)
{
    ///关键码是IP
    unsigned int * number=(unsigned int *)key;
    return (*number)%buckets;
}
///取出一个IP地址保存下来
///当一个客户登录的时候，要在s_ip_count_hash更新这个表中的对应项
///即该ip对应的连接数要加1，如果这个表项还不存在，要在表项中添加一条记录，并将对应的IP连接数加
unsigned int handle_ip_count(void* ip)
{
    unsigned int count;
    unsigned int * p_count=(unsigned int*)hash_lookup_entry(s_ip_count_hash,ip,sizeof(unsigned int));
    if(p_count==NULL)
    {
        count=1;
        hash_add_entry(s_ip_count_hash,ip,sizeof(unsigned int),&count,sizeof(unsigned int));
    }
    else///Ip已经存在
    {
        count=*p_count;
        ++count;
        *p_count=count;
    }
    return count;
}

void drop_ip_count(void *ip)
{
    unsigned int count;
    unsigned int * p_count=(unsigned int*)hash_lookup_entry(s_ip_count_hash,ip,sizeof(unsigned int));
    if(p_count==NULL)
    {
        return ;
    }
       ///得到了IP进而我们就可以在s_ip_count_hash表中找到了对应的连接数，进而可以减1
        count=*p_count;
        if(count<=0)
            return;
        --count;
        *p_count=count;
        if(count==0)
            hash_free_entry(s_ip_count_hash,ip,sizeof(unsigned int));
}







