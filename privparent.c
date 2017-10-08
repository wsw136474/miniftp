//协助进行特殊链接处理模块，协助创建数据通道，内部使用的私有进程，外界不与之联系.
//不断接收服务进程的命令。
//nobody进程接收服务进程的命令。进一步接收一个整数，也就是port。接收一个字符串，也就是IP
//与客户端建立数据连接
#include"privparent.h"
#include "sysutil.h"
#include "privsock.h"
#include "tunable.h"

static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

 int capset(cap_user_header_t hdrp, cap_user_data_t datap)
 {
    return syscall(__NR_capset,hdrp,datap);//系统调用。跟上系统调用号码
 }

void minimize_privilege(void)
{
     //将父进程改为nobody进程
		struct passwd *pw=getpwnam("nobody");
		if(pw==NULL)  return ;
		if(setegid(pw->pw_gid)<0)
			ERR_EXIT("setegid");
		if(seteuid(pw->pw_uid)<0)
			ERR_EXIT("seteuid");
    /*
    给nobody进程增加特权，使它可以绑定20端口
    int capset(cap_user_header_t hdrp, cap_user_data_t datap);
    typedef struct __user_cap_header_struct {
              __u32 version;
              int pid;//set不需要，get才需要
           } *cap_user_header_t;

           typedef struct __user_cap_data_struct {
              __u32 effective;
              __u32 permitted;
              __u32 inheritable;
           } *cap_user_data_t;
    */
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;
    memset(&cap_header,0,sizeof(cap_header));
    memset(&cap_data,0,sizeof(cap_data));
    cap_header.version= _LINUX_CAPABILITY_VERSION_2;//getconf LONG_BIT 命令 返回系统64位
    cap_header.pid=0;

     __u32 cap_mask=0;
    cap_mask|=(1<<CAP_NET_BIND_SERVICE);//这个特权在第十位。需要将第十位置1.1左移CAP_NET_BIND_SERVICE
    cap_data.effective=cap_mask;
    cap_data.permitted=cap_mask;
    cap_data.inheritable=0;
    capset(&cap_header,&cap_data);

}
void handle_parent(session_t* sess)
{

    minimize_privilege();
	char cmd;
	while(1)
	{
	    //从子进程接收命令
		//read(sess->parent_fd,&cmd,1);
       cmd= priv_sock_get_cmd(sess->parent_fd);//服务进程结束后会关闭socketpair套接字，该函数中read返回0，从而退出nobody进程。
		//解析命令
        switch(cmd)
        {
            case PRIV_SOCK_GET_DATA_SOCK:
                privop_pasv_get_data_sock(sess);
                break;
            case PRIV_SOCK_PASV_ACTIV:
                privop_pasv_active(sess);
                break;
            case PRIV_SOCK_PASV_LISTEN:
                privop_pasv_listen(sess);
                break;
            case PRIV_SOCK_PASV_ACCEPT:
                privop_pasv_accept(sess);
                break;
        }
		//处理内部命令
	}
}

//nobody进程创建数据连接套接字并且应答服务进程
static void privop_pasv_get_data_sock(session_t *sess)
{

    /*
    nobody接收PRIV_SOCK_GET_DATA_SOCK命令
    进一步接收有一个port和ip
    fd=socket
    bind(20)
    connect(ip,port)

    ok
    send_fd
    bad
    */
    //接收port
    unsigned short port=(unsigned short)priv_sock_get_int(sess->parent_fd);
    //接收ip
    char ip[16]={0};

    priv_sock_recv_buf(sess->parent_fd,ip,sizeof(ip));
    //填充地址
    struct sockaddr_in addr;
    memset(&addr,0,sizeof(struct sockaddr_in));
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);
    addr.sin_addr.s_addr=inet_addr(ip);

    //建立连接
    int fd=tcp_client(0);//绑定20端口号
    if(fd==-1)
    {

        priv_sock_send_result(sess->parent_fd,PRIV_SOCK_RESULT_BAD);
        return;
    }
    if(connect_timeout(fd,&addr,tunable_connect_timeout)<0)
    {


                close(fd);
                priv_sock_send_result(sess->parent_fd,PRIV_SOCK_RESULT_BAD);
                return ;
    }

    //发送建立连接成功的应答
    priv_sock_send_result(sess->parent_fd,PRIV_SOCK_RESULT_OK);
    //发送数据连接套接字
    priv_sock_send_fd(sess->parent_fd,fd);
    close(fd);
    return ;
}
//协助被动模式判定被动模式是否处于激活状态
static void privop_pasv_active(session_t *sess)
{
    int active;
    if(sess->pasv_listen_fd!=-1)
    {
        active=1;
    }
    else
    {
        active=0;
    }
    priv_sock_send_int(sess->parent_fd,active);
}
//协助被动模式创建监听套接字
static void privop_pasv_listen(session_t *sess)
{

    char ip[16];
	getlocalip(ip);

    sess->pasv_listen_fd=tcp_server(ip,0);//绑定临时端口，返回监听套接字保存到被动连接监听套接字变量中
	struct sockaddr_in addr;
	socklen_t addrlen=sizeof(addr);
	if(getsockname(sess->pasv_listen_fd,(struct sockaddr *)&addr,&addrlen)<0)
	{
		ERR_EXIT("getsockname");
	}
	unsigned short port=ntohs(addr.sin_port);//获取临时端口号

	//把端口号发送给被动模式服务进程
    priv_sock_send_int(sess->parent_fd,(int)port);

}
//协助被动模式创建数据连接套接字，并且回传数据连接套接字
static void privop_pasv_accept(session_t *sess)
{
        int conn=accept_timeout(sess->pasv_listen_fd,NULL,tunable_accept_timeout);
		close(sess->pasv_listen_fd);
		if(conn==-1)
		{
		    priv_sock_send_result(sess->parent_fd,PRIV_SOCK_RESULT_BAD);
			return ;
		}
		 priv_sock_send_result(sess->parent_fd,PRIV_SOCK_RESULT_OK);
         priv_sock_send_fd(sess->parent_fd,conn);
         return;
}
