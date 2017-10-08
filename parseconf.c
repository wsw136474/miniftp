/*
该模块提供两个函数来处理配置文件和配置项。
一个用来加载配置文件，另一个将配置项加载到相应的变量
*/
#include"parseconf.h"
#include"common.h"
#include"tunable.h"
#include "str.h"

//开关配置项
static struct parseconf_bool_setting
{
	const char *p_setting_name;
	int *p_variable;
}parseconf_bool_array[]={
	{"pasv_enable",&tunable_pasv_enable},
	{"port_enable",&tunable_port_enable},
	{NULL,NULL}
};

//无符号整型配置项
static struct parseconf_uint_setting
{
	const char* p_setting_name;
	unsigned int* p_variable;
}parseconf_uint_array[]={
    {"listen_port",&tunable_listen_port},
    {"max_clients",&tunable_max_clients},
    {"max_per_ip",&tunable_max_per_ip},
    {"accept_timeout",&tunable_accept_timeout},
    {"connect_timeout",&tunable_connect_timeout},
    {"idle_session_timeout",&tunable_idle_session_timeout},
    {"data_connection_timeout",&tunable_data_connection_timeout},
    {"local_umask",&tunable_local_umask},
    {"upload_max_rate",&tunable_upload_max_rate},
    {"download_max_rate",&tunable_download_max_rate},
    {NULL,NULL}
};
//字符串配置项信息
static struct parseconf_str_setting
{
    const char *p_setting_name;
    const char **p_variable;
}parseconf_str_array[]={
    {"listen_address",&tunable_listen_address},
    {NULL,NULL}
};




//加载配置文件
void parseconf_load_file(const char *path)
{
	FILE *fp=fopen(path,"r");
	if(fp==NULL)
		ERR_EXIT("fopen");
	char setting_line[1024]={0};
	while(fgets(setting_line,sizeof(setting_line),fp)!=NULL)
	{
		//读取的一行为空或者首字符为#注释，或者字符串全空
		if(strlen(setting_line)==0||setting_line[0]=='#'||str_all_space(setting_line))
			continue;
		//去除换行符
		str_trim_crlf(setting_line);
		parseconf_load_setting(setting_line);
		memset(setting_line,0,sizeof(setting_line));		
	}
	fclose(fp);
}

//将配置项加载到相应的变量. setting指向待设置配置项
void parseconf_load_setting(const char *setting)
{
	//   AA=111 先解析key和value
	while(isspace(*setting))
		setting++;
	char key[128]={0};
	char value[128]={0};
	str_split(setting,key,value,'=');
	if(strlen(value)==0)
	{
		fprintf(stderr,"missing value in config file for: %s\n",key);
		exit(EXIT_FAILURE);
	}

	{
		const struct parseconf_str_setting *p_str_setting=parseconf_str_array;
		while(p_str_setting->p_setting_name!=NULL)
		{
			if(strcmp(key,p_str_setting->p_setting_name)==0)
			{
				const char**p_cur_setting=p_str_setting->p_variable;
				if(*p_cur_setting)
					free((char *)*p_cur_setting);
		//strdup()在内部调用了malloc()为变量分配内存，不需要使用返回的字符串时，需要用free()释放相应的内存空间.value是局部变量
				*p_cur_setting=strdup(value);
				 return ;
			}
			p_str_setting++;
		}
	}
	
	{
		const struct parseconf_bool_setting *p_bool_setting=parseconf_bool_array;
		while(p_bool_setting->p_setting_name!=NULL)
		{
			if(strcmp(key,p_bool_setting->p_setting_name)==0)
			{	
				//AA=yes  AA=TRUE
				str_upper(value);
				if(strcmp(value,"YES")==0||strcmp(value,"TRUE")==0||strcmp(value,"1")==0)
					*(p_bool_setting->p_variable)=1;
				else if(strcmp(value,"NO")==0||strcmp(value,"FALSE")==0||strcmp(value,"0")==0)
					*(p_bool_setting->p_variable)=0;
				else{
					fprintf(stderr,"bad bool value in config file for: %s\n",key);
					exit(EXIT_FAILURE);
				}
				return ;
					
			}
			p_bool_setting++;
		}

	}

	{
		const struct parseconf_uint_setting *p_uint_setting=parseconf_uint_array;
		while(p_uint_setting->p_setting_name!=NULL)
		{
			if(strcmp(key,p_uint_setting->p_setting_name)==0)
			{	
				//listen_pot=21
				//umask=077 八进制
				if(value[0]=='0')
					*(p_uint_setting->p_variable)=str_octal_to_uint(value);
				else
					*(p_uint_setting->p_variable)=atoi(value);
				return ;
					
			}
			p_uint_setting++;
		}

	}

}

























