#!/usr/bin/python
# -*- coding: utf-8 -*-
# File name: mta-reject-guncelleyici.py
# Author: Koray YILMAZ
# Date created: 31/07/2015
# Date last modified: 04/08/2015
# Python Version: 2.7.5
# Description: parses the url in the url and updates the
#              /opt/zimbra/postfix/conf/reject file 
# Requirement: passswordless ssh to server, paramiko

# -*- coding: utf-8 -*-
from __future__ import print_function
from xml.dom import minidom
from xml.dom.minidom import Document
import urllib2
import sys
import os
import socket
import paramiko
import datetime
import smtplib
from email.mime.text import MIMEText

def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

def get_usomlist(url):
    # get the malicious urls from the url db
    #'https://www.usom.gov.tr/url-list.xml'
    file = urllib2.urlopen(url)
    data = file.read()

    # parse string
    xmldoc = minidom.parseString(data)
    itemlist = xmldoc.getElementsByTagName('url')

    # get the url values in the tree
    usomlist=[]
    for item in itemlist:
        #regular expression control
        #http veya / veya 31 sayı olmamalı!
        url = str(item.firstChild.nodeValue)
        if not('/' in url or 'html' in url or  'http' in url or
               valid_ip(url)):
            usomlist.append(url.strip())
    return usomlist

def get_curr_rejects(remote_reject_file_path, server_name, port=22):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(server_name, port=port)
    sftp_client = client.open_sftp()
    remote_file = sftp_client.open(remote_reject_file_path, 'r')
    rejectlist = []
    try:
        for line in remote_file:
            rejectlist.append(line.split(' ')[0].strip())
    finally:
        remote_file.close()
        client.close()
    return rejectlist

def write_new_rejects(remote_reject_file_path, server_name, rejectlist, port=22):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(server_name, port=port)
    sftp_client = client.open_sftp()
    rejectlist = [s + ' REJECT' for s in rejectlist]
    remote_file = sftp_client.open(remote_reject_file_path, 'a+')
    remote_file.writelines('\n'.join(rejectlist))
    remote_file.write('\n')
    remote_file.close()
    client.close()

def cmd_postfix(server_name, cmd, port=22):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.connect(server_name,port=port)
    stdin, stdout, stderr = client.exec_command(cmd)
    result = stdout.readlines()
    client.close()
    print(result)
    return result



def main():
    USOM_ZARARLILAR = 'https://www.usom.gov.tr/url-list.xml'
    POSTFIX_SERVER_NAME = 'mta01'
    REMOTE_REJECT_FILE = '/opt/zimbra/postfix/conf/reject'
    SMTP_SERVER_NAME = 'mail.bilgi.tubitak.gov.tr'
    SSH_PORT = 22
    CMD1 = 'sudo su - zimbra -c "/opt/zimbra/postfix/sbin/postmap ' + REMOTE_REJECT_FILE + '"'
    CMD2 = 'sudo su - zimbra -c  "/opt/zimbra/bin/zmmtactl stop" && sudo su - zimbra -c  "/opt/zimbra/bin/zmmtactl start"'

    #TODO: tekrar eden paramiko kodlari tek fonk. alinabilir
    #TODO: harcoded yerler parametrik yapilabilir.
    if len(sys.argv) >= 2:
        POSTFIX_SERVER_NAME = sys.argv[1]
        if sys.argv[1] == 'ldap03':
            REMOTE_REJECT_FILE = '/etc/postfix/access'
            SSH_PORT = 32032
            CMD1 = 'sudo -c "/usr/sbin/postmap ' + REMOTE_REJECT_FILE + '"'
            CMD2 = 'sudo -c "/etc/init.d/postfix restart"'
            
    if len(sys.argv) == 1:
        print("Kullaim: ./mta-reject-guncelleyici <postfix sunucu> <opsiyonel: engellenecek domain adi>")
        sys.exit(1)
    
        
    filepath = os.path.dirname(os.path.abspath('__file__'))
    today = datetime.datetime.now()
    log_file_name = POSTFIX_SERVER_NAME + "_" + today.strftime('%Y%m%d-%H%M') + ".log"
    

    usomlist = get_usomlist(USOM_ZARARLILAR)
    print('\n'.join(usomlist))

    if len(sys.argv) == 3:
        #TODO: girdi kontrol, assert ve regex search eklenecek
        usomlist.append(sys.argv[2])

    current_rejectlist = get_curr_rejects(REMOTE_REJECT_FILE, POSTFIX_SERVER_NAME, SSH_PORT)
    diff_rejectlist = []

    cnt = 0
    for item in usomlist:
        if not item in current_rejectlist:
            current_rejectlist.append(item)
            diff_rejectlist.append(item)
            cnt += 1

    print("########################")
    print('\n'.join(current_rejectlist))
    if cnt > 0:
        logfp = open(os.path.join(filepath, log_file_name), 'a+')
        write_new_rejects(REMOTE_REJECT_FILE, POSTFIX_SERVER_NAME, diff_rejectlist, port=SSH_PORT)
        print('\n'.join(diff_rejectlist), file=logfp)
        print("USOM'dan ",cnt,"kadar yeni zararli domain eklendi:", file=logfp)        
        cmd_postfix(POSTFIX_SERVER_NAME, CMD1, SSH_PORT)
        res = cmd_postfix(POSTFIX_SERVER_NAME, CMD2, SSH_PORT)
        print("\npostfix sunucu durumu:\n", res, file=logfp)
        logfp.close()
        fp = open(os.path.join(filepath, log_file_name), 'rb')
        #send results to smtp server
        msg = MIMEText(fp.read())
        msg['Subject'] = POSTFIX_SERVER_NAME + ' reject domain script log' + log_file_name
        msg['From'] = 'admin@tubitak.gov.tr'
        msg['To'] = 'sdestek@tubitak.gov.tr'
        s = smtplib.SMTP(SMTP_SERVER_NAME)
        s.sendmail(msg['From'] ,msg['To'],msg.as_string())
        fp.close()
    else:
        print("USOM ile postfix reject guncel")
        print(POSTFIX_SERVER_NAME)


if __name__ == '__main__':
    main()
