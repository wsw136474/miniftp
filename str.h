#ifndef _STR_H_
#define _STR_H_
#include "common.h"
//去除\r\n
void str_trim_crlf(char* str);
//字符串分割
void str_split(const char *str,char* left,char* right,char c);
//判断是否全是空白字符
int str_all_space(char* str);
//字符串转换为大写格式
void str_upper(char* str);
//将字符串转换为long long
long long str_to_longlong(const char* str);
//将字符串（八进制）转换为无符号整型
unsigned int str_octal_to_uint(const char* str);

#endif
