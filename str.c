/*
字符串处理模块
*/
#include "str.h"
#include"common.h"
//去除\r\n
void str_trim_crlf(char* str)
{
	char *p=&str[strlen(str)-1];
	while(*p=='\r'||*p=='\n')
	{
		*p--='\0';
	}
}
//字符串分割，以c字符分割.第一个参数：待分割字符串。分割出来的命令放到left,分割出来的参数放到right
void str_split(const char *str,char* left,char* right,char c)
{
	char *p=strchr(str,c);//该函数可以查找字符串s中首次出现字符c的位置。
	if(p==NULL)//命令不带参数
	{
		strcpy(left,str);
	}
	else {
		strncpy(left,str,p-str);//空格前
		strcpy(right,p+1);//空格后
	}

}
//判断是否全是空白字符
int str_all_space(char* str)
{
	while(*str)
	{
		if(!isspace(*str))//输入字符是否为空（空格/回车/制表符）
			return 0;
		str++;
	}
	return 1;
}
//字符串转换为大写格式
void str_upper(char* str)
{
	while(*str)
	{
		*str=toupper(*str);
		str++;
	}

}
//将字符串转换为long long
long long str_to_longlong(const char* str)
{
	//return  atoll(str);//库函数
	long long result=0;
	long long mult=1;
	unsigned int len=strlen(str);
	unsigned int i;
	long long val;
	if(len>15)
		return 0;
	for(i=0;i<len;i++)
	{
		char ch=str[len-(i+1)];
		if(ch<'0'||ch>'9')
			return 0;
		val=ch-'0';
		val*=mult;
		mult*=10;
		result+=val;
	}
	return result;
	
}
//将字符串（八进制）转换为无符号整型  123456745 ----5*1+4*8+7*8^2+...
//法二：0*8+1     1*8+2=10    10*8+3=83   ...
unsigned int str_octal_to_uint(const char* str)
{
	unsigned int result=0;
	int seen_non_zero_digit=0;
	while(*str)
	{
		char digit=*str;
		if(!isdigit(digit)||digit>'7')
			break;
		if(digit!='0')
			seen_non_zero_digit=1;
		if(seen_non_zero_digit)
		{
			result=result*8+(digit-'0');
		}
		str++;
	}
	return result;
}

















