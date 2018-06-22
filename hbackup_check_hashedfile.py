#!/usr/bin/python3

debug = False

import sys
import os
import datetime
import time
import hashlib
import argparse

parser = argparse.ArgumentParser(
    description='hbackup workdir hashedfile check')
parser.add_argument(dest='workdir', metavar='hbackup_workdir')
parser.add_argument('-d', dest='debug', action='store_true', help='debug mode')
args = parser.parse_args()


def md5sum(filename, blocksize=65536):
    hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            hash.update(block)
    return hash.hexdigest()


hashed_dir = args.workdir
debug = args.debug

print("checking dir " + args.workdir)

hashed_dir = sys.argv[1] + "/hashed_file"
if not os.path.isdir(hashed_dir):
    print(hashed_dir + " is not a directory")
    sys.exit(-1)

for root, dirs, files in os.walk(hashed_dir, topdown=True):
    for name in files:
        file_name = os.path.join(root, name)
        print(file_name, end='')
        if name[32:33] != '_':
            print(" " + file_name + " ERROR invalid file name")
            continue
        file_md5sum = name[0:32]
        file_len = int(name[33:])
        if os.path.isfile(file_name):
            if md5sum(file_name) == file_md5sum:
                statinfo = os.stat(file_name)
                print(" OK %d" % statinfo.st_nlink)
            else:
                print(" ERROR md5sum")
                sys.exit(-1)
        else:
            print(" ERROR not a file")
