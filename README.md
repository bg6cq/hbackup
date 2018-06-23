## 基于md5sum的文件备份程序

https://github.com/bg6cq/hbackup

Author: Zhang Huanjie james@ustc.edu.cn


优点：

* 非常简单，服务器端C代码900行，客户端python3代码200余行。
* 多次备份，相同的文件（文件长度和md5sum都一样）仅传输1次，仅占用服务器上1份空间。
* 客户端仅允许上传新文件，无法读文件，也永远无法覆盖之前备份过的文件。即便备份密码泄漏也无数据泄漏隐患。

## 服务器端

`make`后生成`hbackup_server`是服务器端程序，执行时命令行如下：

```
# ./hbackup_server 
Usage:
./hbackup_server options
 options:
    -p port
    -f config_file
    -u user_name    change to user before write file
    -6              enable ipv6 listen
    -d              enable debug

config_file配置文件，内容是如下的若干行（work_dir需要在备份文件之前建立，并且对user_name可读写）:
password work_dir
password2 work_dir2

其中： 

-p 指明使用的tcp端口
-f 是配置文件
-u 是上传后文件的属主
-d 是开启调试模式，会显示一些调试信息

客户端验证密码后，会把文件上传到workdir目录下
```

`hbackup_check_hashedfile.py` 是检查`hashed_file`目录下完整性的程序。


## 客户端

客户端为python 3程序，命令行是:
```
python3 hbackup.py 
Usage: python3 hbackup.py [ -e err.log ] [ -x exclude_file_regex ] [ -t n ] [ -d ] HostName PortNumber Password File/DirToSend [ new_name ]

* 如果带有参数`-e err.log`，出现备份时错误时，会将未备份的文件信息记录在文件`err.log`，并继续其他文件的备份。
* 如果不带参数`-e err.log`，出现错误立即停止后续备份过程。
* -x 可以有若干个，跳过匹配正则表达式的文件，如 -x ".*test" 可以跳过所有文件名中有test的文件
* -t n，跳过最后修改时间是n天前的文件
* 最后的可选参数是服务器上的目录名，每次备份可以使用不同的名字区分。

```

## 工作原理

系统工作的前提：不存在同样长度的文件，它们的md5sum相同。

假定工作目录是/，工作目录中有2个文件夹:

* hashed_file/，存放有所有的备份文件，这个目录仅仅新增文件。格式如`hashed_file/ab/cd/abcdefxxxx_size`，其中abceefxxxxxx是文件的md5sum(长度是32字节，全部是小写字母)，size是文件长度。为了减少单个目录下文件数量，分2级目录散列存储。
* data/，存放备份文件。备份时，同样的文件在hashed_file下仅仅存1份。data/目录下的文件是到hashed_file的hard link，不占额外空间。也就是说相同文件（md5sum相同，长度相同）的文件，无论备份多少次，只存1份。

## 通信协议

通信协议非常简单，客户端与服务器建立连接后(涉及目录名/文件名的地方使用urlencode以方便特殊字符路径名/文件名):

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

2.3 除了发送文件外，还支持以下2个命令：

```
MKDIR dir_name #用于创建目录
MKLINK new_name old_name  #用于创建软连接
```

