#!/usr/bin/python

import socket
import sys
import os

import hashlib
def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()

if len(sys.argv) < 5:
    print 'Usage: python %s <HostName> <PortNumber> <Password> <FileToSend> [ file_new_name ]' % (sys.argv[0])
    print 'FileToSend - means read from stdin'
    sys.exit();

host=sys.argv[1]
port=int(sys.argv[2])
pass_word=sys.argv[3]
file_name=sys.argv[4]
if len(sys.argv) == 6:
	file_new_name=sys.argv[5]
else:
	file_new_name=file_name

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error, msg:
        print 'Failed to creat socket. Error code: ' + str(msg[0]) + ' Error message: ' + msg[1]
        sys.exit();
try:
        host_ip=socket.gethostbyname(host)
except socket.gaierror:
        print 'Host name could not be resolved. Exiting...'
        sys.exit();

print 'IP address of ' + host + ' is ' + host_ip + ' .'

try:
    s.connect((host_ip, port)) 
except socket.error, (value,message):
    if s:
        s.close();
    print 'Socket connection is not established!\t' + message
    sys.exit(1);

print 'Socket connected to ' + host + ' on IP ' + host_ip + ' port ' + str(port) + '.'

s.send('PASS '+pass_word+'\n')
data = s.recv(100)
print 'S', data
if data[0:2] != 'OK':
    print 'exit with return code 255'
    sys.exit(-1)

filemd5sum = md5sum(file_name)
file_size = os.path.getsize(file_name)
print filemd5sum + "_"+ str( file_size)
s.send('FILE '+filemd5sum+' '+str(file_size) + ' '+file_new_name+'\n')
data = s.recv(100)
print 'S', data
if data[0:2] == 'OK':
    print 'OK, exit with return code 0'
    s.send('END\n')
    sys.exit(0)

if data[0:4] == 'DATA':
    print "I will send file"
    CHUNKSIZE=1024*1024
    file = open(file_name, "rb")
    bytes_send = 0
    try:
        while True:
            need_read = file_size - bytes_send
            if need_read > 0:
                 if need_read > CHUNKSIZE:
                     bytes_read = file.read(CHUNKSIZE)
                 else:
                     bytes_read = file.read(need_read)
            if bytes_read:
                s.send(bytes_read);
                bytes_send += len(bytes_read)
            else:
                break;
    finally:
        file.close()
    data = s.recv(100)
    print 'S', data
    if data[0:2] == 'OK':
        print 'OK, exit with return code 0'
        s.send('END\n')
        sys.exit(0)
    else:
        sys.exit(-1)
