# 服务器端初步可以工作，客户端只能单个文件上传

## 适用于文件备份的程序

系统工作的前提：不存在同样长度的文件，它们的md5sum相同。

假定工作目录是/，系统中有个特殊的文件夹hashed_file，存放有所有的备份文件，这个目录仅仅新增文件。
hashed_file/ab/cd/abcdefxxxx_size     xxxxxx是文件的md5sum，长度是32字节，全部是小写字母，size是文件大小。为了减少单个目录下文件数量，分2级目录存储。

## 通信协议

通信协议非常简单，客户端与服务器建立连接后:

2.1 客户端发送
```
PASS 密码\n
```
用来验证身份，通过验证后，服务器返回
```
OK password ok\n
```

2.2 客户端发送
```
FILE md5sum 文件长度 文件名\n
```
如果文件名已经存在，服务器返回
```
ERROR file exist\n
```

如果同样md5sum、文件长度的文件已经在hashed_file下存在，且文件名不存在，服务器端建立一个硬连接，并返回
```
OK file in server\n
```

如果hashed_file文件不存在，服务器返回
```
DATA I need your data\n
```
客户端把文件内容上传（写文件长度）数据，服务器端正确收到后，存放在hashed_file下，建立硬连接，并返回
```
OK file in server now\n
```

重复2.2，直到所有文件上传完毕，客户端发送以下命令关闭连接
```
END\n
```
服务器返回
```
BYE upload_size of total_file_size \n
```

## 服务器端

hbackup_server是服务器端程序，执行时命令行如下：

```
# ./hbackup_server 
Usage:
./hbackup_server options
 options:
    -p port
    -f config_file
    -u user_name    change to user before write file

    -d              enable debug

config_file:
password work_dir

其中： 

-p 指明使用的tcp端口
-f 是配置文件
-u 是上传后文件的属主
-d 是开启调试模式，会显示一些调试信息

配置文件格式为：
密码 目录

客户端验证密码后，会把文件上传到目录下
```


## 客户端

客户端为python程序，命令行是:
```
./hbackup.py 
Usage: python ./hbackup.py <HostName> <PortNumber> <Password> <FileToSend> file_new_name

最后可选参数是服务器重命名文件。
```
