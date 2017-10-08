//建立会话模块
#include"session.h"
#include"sysutil.h"
#include"ftpproto.h"
#include"privparent.h"
#include"privsock.h"
void begin_session(session_t* sess)
{
    ///开启能够接受紧急数据的功能,用于abor命令
    activate_oobinline(sess->ctrl_fd);
	/*  struct passwd *getpwnam(const char *name);
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
    /*
	int sockfds[2];//进行父子进程通信
	if(socketpair(PF_UNIX,SOCK_STREAM,0,sockfds)<0)
		ERR_EXIT("socketpair");
	*/
	priv_sock_init(sess);

	pid_t pid;
	pid=fork();
	if(pid==-1)
		ERR_EXIT("fork");
	//子进程是ftp服务进程
	if(pid==0)
	{
	    /*在privsock中模块化
		close(sockfds[0]);
		sess->child_fd=sockfds[1];
		*/
		priv_sock_set_child_context(sess);
		handle_child(sess);//服务进程模块
	}
	//父进程是nobody进程.nobody进程的父进程是root进程
	else
	{
    /*
		 //将父进程改为nobody进程
		struct passwd *pw=getpwnam("nobody");
		if(pw==NULL)  return ;
		if(setegid(pw->pw_gid)<0)
			ERR_EXIT("setegid");
		if(seteuid(pw->pw_uid)<0)
			ERR_EXIT("seteuid");
    */
    /*
		close(sockfds[1]);
		sess->parent_fd=sockfds[0];
    */
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}
