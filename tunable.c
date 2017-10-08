#include"tunable.h"
int tunable_pasv_enable=1;//是否开启被动模式。默认是
int tunable_port_enable=1;//是否开启主动模式。
unsigned int tunable_listen_port=21;//FTP服务器端端口
unsigned int tunable_max_clients=2000;//最大连接数
unsigned int tunable_max_per_ip=50;//每个IP最大连接数
unsigned int tunable_accept_timeout=60;//accept超时时间
unsigned int tunable_connect_timeout=60;//connect超时时间
unsigned int tunable_idle_session_timeout=30;//控制连接超时时间
unsigned int tunable_data_connection_timeout=30;//数据连接超时时间
unsigned int tunable_local_umask=077;//掩码
unsigned int tunable_upload_max_rate=1024;//最大上传速度,每秒字节
unsigned int tunable_download_max_rate=204800;//最大下载速度
const char *tunable_listen_address;//FTP服务器IP地址
