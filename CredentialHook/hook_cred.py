# -*- coding:utf-8


# Refer to https://github.com/google/ssl_logger/blob/master/ssl_logger.py
# Origin: https://github.com/fanxs-t/Android-SSL_read-write-Hook/blob/master/frida-hook.py
# Author : Fanxs
# 2019-12-16

# Rewrite: k1rh4 (2020-0720)

import frida
import sys
import os
import signal
import socket
import struct
import hexdump
import time
import random
import csv
import queue
import re
from urllib.parse import unquote
from termcolor import colored, cprint


#application = ["com.xiaomi.smarthome"]
application = "com.example.prjjni"
print("Attack: %s"%application)

pcap = os.path.join(os.getcwd(),"log.pcap")
_FRIDA_SCRIPT = open("hook_cred.js","r").read()

# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions        = {}
requests_queue_list = {}              # queue.Queue(20)
response            = ""
response_flag       = False           # True if any response was received


def dlog_message(data, LOG_INFO):
  PATTERN     = ['session','accessToken','secret','key','client_id','uuid','appId']
  color_enum  = ['red','green','blue','yellow']
  color_cnt   = 0 
  show_data = unquote(str(data))

  for p in PATTERN:
    if( type(data) == type(b'bytes')):
      if data.find( p.encode() ) >=0 :
        show_data = show_data.replace(p,colored(p,color_enum[(color_cnt% 4)]))
        color_cnt +=1

    elif(type(data) == type('str')):
      if data.find( p ) >=0 :
        show_data = show_data.replace(p,colored(p,color_enum[(color_cnt% 4)]))
        color_cnt +=1

    else:
      print("[-] unknown type..")

  if( color_cnt ): 
    print("%s"% LOG_INFO )
    print (show_data+"\n")


def sharedPreference_hook(message):
  p           = message["payload"]
  data_key    = p["data_key"]
  data_value  = p["data_value"]
  data        = data_key + "=" +data_value
  LOG_INFO    = "[+] Call->SharedPreference"
  print(LOG_INFO)
  dlog_message(data, LOG_INFO)  # type(data) == str

def dlopen_hook():
  pass

def native_call_hook():
  pass

def SQLi_hook():
  pass

def on_message(message, data):
  # print(repr(message))
  # print(repr(data))
  if message["type"] == "error":
    os.kill(os.getpid(), signal.SIGTERM)
    return

  if(message['payload']['function'] =='SharedPrefernece'):
    sharedPreference_hook(message)

  else:
    pass

if __name__ == "__main__":
  # pcap logging
  print("[+] START")
  print("[I] Press Ctrl+C to stop logging.")

  if(1==1):
    session = frida.get_usb_device().attach(application)
  else:
    device  = frida.get_usb_device()
    pid = device.spawn(application)
    device.attach(pid)
    device.resume(pid)

  script = session.create_script(_FRIDA_SCRIPT)
  script.on('message', on_message)
  script.load()

  try:
      sys.stdin.read()
  except KeyboardInterrupt:
      pass
  session.detach()
  exit(0)