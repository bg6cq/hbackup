# 服务器端初步可以工作，客户端只能上传单个文件

## 适用于文件备份的程序

系统工作的前提：不存在同样长度的文件，它们的md5sum相同。

假定工作目录是/，系统中有2个特殊的文件夹:

* hashed_file/，存放有所有的备份文件，这个目录仅仅新增文件。格式如`hashed_file/ab/cd/abcdefxxxx_size`，其中abceefxxxxxx是文件的md5sum(长度是32字节，全部是小写字母)，size是文件长度。为了减少单个目录下文件数量，分2级目录散列存储。
* data/，存放备份文件。备份时，同样的文件在hashed_file下仅仅存1份。data/目录下的文件是到hashed_file的hard link，不占额外空间。也就是说相同文件（md5sum相同，长度相同）的文件，无论备份多少次，只存1份。

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

目前客户端不完善，只能单个文件备份，而且速度不算快：
```
假定要备份 /usr/src/wlan 下的文件，可以：

cd /usr/src/wlan; find .  -type f | grep -v "^.$" | while read f; do
echo $f
/usr/src/hbackup/hbackup.py 127.0.0.1 99 test $f 20180612/$f
done
```
