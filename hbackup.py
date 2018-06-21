#!/usr/bin/python3

debug = False

import socket
import sys
import os
import datetime  
import time 
import urllib.parse
import hashlib

def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

def end_hbackup(retcode = 0):
    s.send('END\n'.encode())
    data = s.recv(100).decode()
    print ('S', data,end='')
    print ('end')
    print ('FDL: %d/%d/%d U/A: %d/%d' % (total_files, total_dirs, total_links, upload_file_len, total_file_len))
    sys.exit(retcode)
    
def send_dir(remote_name):
    global total_dirs
    total_dirs += 1
    s.send(('MKDIR ' + urllib.parse.quote(remote_name) + '\n').encode())
    data = s.recv(100).decode()
    if data[0:2] == 'OK':
        print("")
        if debug:
            print ('S', data,end='')
        return
    print (' S', data,end='')
    log_err(remote_name+' '+ data)

def send_link(remote_name, linkto):
    global total_links
    total_links += 1
    s.send(('MKLINK ' + urllib.parse.quote(remote_name) + ' ' + urllib.parse.quote(linkto) + '\n').encode())
    data = s.recv(100).decode()
    if data[0:2] == 'OK':
        print("")
        if debug:
            print ('S', data,end='')
        return
    print (' S', data,end='')
    log_err(remote_name+' '+ data)

def send_file(local_file_name, remote_name):
    global total_files, total_file_len, upload_file_len
    total_files += 1 
    filemd5sum = md5sum(local_file_name)
    file_size = os.path.getsize(local_file_name)
    total_file_len += file_size
    if debug:
        print (filemd5sum + "_" + str( file_size))
    s.send(('FILE ' + filemd5sum + ' ' + str(file_size) + ' ' + urllib.parse.quote(remote_name) + '\n').encode())
    data = s.recv(100).decode()
    if data[0:2] == 'OK':
        if debug:
            print ('S', data,end='')
        print("")
        return
    if data[0:5] == 'ERROR':
        print (' S', data,end='')
        log_err(local_file_name +' --> '+ remote_name + ' ' + data)
        return
    if data[0:4] == 'DATA':
        if debug:
            print ('S', data,end='')
            print ("I will send file")
        CHUNKSIZE=1024*1024
        file = open(local_file_name, "rb")
        bytes_send = 0
        try:
            while True:
                need_read = file_size - bytes_send
                if need_read > 0:
                     if need_read > CHUNKSIZE:
                         bytes_read = file.read(CHUNKSIZE)
                     else:
                         bytes_read = file.read(need_read)
                     if len(bytes_read)>0:
                         upload_file_len += len(bytes_read)
                         s.send(bytes_read)
                         bytes_send += len(bytes_read)
                     else:
                         break
                else:
                    break
        finally:
            file.close()
        data = s.recv(100).decode()
        if data[0:2] == 'OK':
            if debug:
                print ('S', data,end='')
            print("")
            return
    print ('S', data,end='')
    end_hbackup(-1)

def usage():
    print ('Usage: python3 %s [ -e err.log ] HostName PortNumber Password File/DirToSend [ Remote_Name ]' % (sys.argv[0]))
    print ('  if -e err.log, error msg will be write to err.log, and continue to run')
    sys.exit();

def log_err(msg):
    if err_log == "":
        print(msg)
        exit(-1)
    f = open(err_log, 'a')  
    now = datetime.datetime.now() 
    f.write(str(now)+' '+msg)  
    f.close()  
        
total_files=total_dirs=total_links=total_file_len=upload_file_len=0

if len(sys.argv) < 5:
    usage()

err_log=""
if sys.argv[1] == "-e":
    if len(sys.argv) < 7:
        usage()
    err_log=sys.argv[2]
    host=sys.argv[3]
    port=int(sys.argv[4])
    pass_word=sys.argv[5]
    file_name=sys.argv[6]
    if len(sys.argv) == 8:
        file_new_name=sys.argv[7]
    else:
        file_new_name=file_name
else:
    host=sys.argv[1]
    port=int(sys.argv[2])
    pass_word=sys.argv[3]
    file_name=sys.argv[4]
    if len(sys.argv) == 6:
        file_new_name=sys.argv[5]
    else:
        file_new_name=file_name

print ("a")
 
try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
except socket.error:
    print ('Failed to creat socket. Error code: ' + str(msg[0]) + ' Error message: ' + msg[1])
    sys.exit(-1);
try:
    host_ip=socket.gethostbyname(host)
except socket.gaierror:
    print ('Host name could not be resolved. Exiting...')
    sys.exit(-1);

try:
    s.connect((host_ip, port)) 
except socket.error:
    if s:
        s.close();
    print ('Socket connection is not established!\t' + message)
    sys.exit(1);
if debug:
    print ('Connected to ' + host + ' on IP ' + host_ip + ' port ' + str(port) + '.')

s.send(('PASS '+pass_word+'\n').encode())
data = s.recv(100).decode()
if data[0:2] != 'OK':
    if debug:
        print ('S', data, end='')
        print ('exit with return code 255')
    sys.exit(-1)

if os.path.islink(file_name):
    print(file_name + " is symlink")
    linkto=os.readlink(file_name)
    send_link(file_new_name, linkto)
    end_hbackup()

if os.path.isfile(file_name):
    print(file_name + " is file")
    send_file(file_name, file_new_name)
    end_hbackup()

if not os.path.isdir(file_name):
    print(file_name + " is not symlink, file, dir, I do not know how to deal")
    end_hbackup()

print(file_name + " is dir")

for root, dirs, files in os.walk(file_name, topdown=True):
    for name in files:
        local_file_name=os.path.join(root,name)
        remote_file_name=file_new_name+'/'+root[len(file_name)+1:]+'/'+name
        if os.sep == "\\":
            remote_file_name = remote_file_name.replace("\\","/")
        if debug:
            print ("F root="+root+" name="+name+" file_new_name="+file_new_name)
            print(local_file_name + " --> "+remote_file_name)
        if os.path.islink(local_file_name):
            print(local_file_name + " is symlink", end='')
            linkto=os.readlink(local_file_name)
            send_link(remote_file_name, linkto)
        elif os.path.isfile(local_file_name):
            print(local_file_name, end='')
            if debug:
                print(" is file")
            send_file(local_file_name, remote_file_name)
        else:
            print(local_file_name, " SKIP")

    for name in dirs:
        local_file_name=os.path.join(root,name)
        remote_file_name=file_new_name + '/' + root[len(file_name)+1:] + '/' + name
        if os.path.islink(local_file_name):
            print(local_file_name + " is symlink", end='')
            linkto=os.readlink(local_file_name)
            send_link(remote_file_name, linkto)
            continue
        print(os.path.join(root,name) + " is dir", end='')
        if os.sep == "\\":
            remote_file_name=remote_file_name.replace("\\","/")
        send_dir(remote_file_name)

end_hbackup()
