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
application = "com.xiaomi.smarthome"

pcap = os.path.join(os.getcwd(),"log.pcap")
_FRIDA_SCRIPT = open("ssl_hook.js","r").read()

# ssl_session[<SSL_SESSION id>] = (<bytes sent by client>,
#                                  <bytes sent by server>)
ssl_sessions        = {}
requests_queue_list = {}              # queue.Queue(20)
response            = ""
response_flag       = False           # True if any response was received

def log_pcap(pcap_file, ssl_session_id, function, src_addr, src_port, dst_addr, dst_port, data):
    """Writes the captured data to a pcap file.
    Args:
      pcap_file: The opened pcap file.
      ssl_session_id: The SSL session ID for the communication.
      function: The function that was intercepted ("SSL_read" or "SSL_write").
      src_addr: The source address of the logged packet.
      src_port: The source port of the logged packet.
      dst_addr: The destination address of the logged packet.
      dst_port: The destination port of the logged packet.
      data: The decrypted packet data.
    """
    t = time.time()

    if ssl_session_id not in ssl_sessions:
      ssl_sessions[ssl_session_id] = (random.randint(0, 0xFFFFFFFF),
                                      random.randint(0, 0xFFFFFFFF))
    client_sent, server_sent = ssl_sessions[ssl_session_id]

    if function == "SSL_read":
        # Responses/ ACK = SEQ + 1
        seq, ack = (server_sent, client_sent + 1)
    else:
        # Requests
        seq, ack = (client_sent, server_sent)

    for writes in (
        # PCAP record (packet) header
        ("=I", int(t)),                        # Timestamp seconds
        ("=I", int((t * 1000000) % 1000000)),  # Timestamp microseconds
        ("=I", 40 + len(data)),           # Number of octets saved
        ("=i", 40 + len(data)),           # Actual length of packet
        # IPv4 header
        (">B", 0x45),                     # Version and Header Length
        (">B", 0),                        # Type of Service
        (">H", 40 + len(data)),           # Total Length
        (">H", 0),                        # Identification
        (">H", 0x4000),                   # Flags and Fragment Offset
        (">B", 0xFF),                     # Time to Live
        (">B", 6),                        # Protocol
        (">H", 0),                        # Header Checksum
        (">I", src_addr),                 # Source Address
        (">I", dst_addr),                 # Destination Address
        # TCP header
        (">H", src_port),                 # Source Port
        (">H", dst_port),                 # Destination Port
        (">I", seq),                      # Sequence Number
        (">I", ack),                      # Acknowledgment Number
        (">H", 0x5018),                   # Header Length and Flags
        (">H", 0xFFFF),                   # Window Size
        (">H", 0),                        # Checksumd
        (">H", 0)):                       # Urgent Pointer
        pcap_file.write(struct.pack(writes[0], writes[1]))
    pcap_file.write(data)

    if function == "SSL_read":
        remaining_length = requests_queue_list[dst_port]["Response"][0]
        #process_response(dst_port, data, remaining_length)
    else:
        req = str(data)[2:-1]
        if(src_port not in requests_queue_list.keys()):
            requests_queue_list[src_port] = {"Request":queue.Queue(20), "Response":[0, ""]}
        requests_queue_list[src_port]["Request"].put(req)
        
    if function == "SSL_read": server_sent += len(data)
    else: client_sent += len(data)
    ssl_sessions[ssl_session_id] = (client_sent, server_sent)

def dlog_message(data, LOG_INFO):
  PATTERN     = ['session','token','Token','secret','key']
  color_enum  = ['red','green','blue','yellow']
  color_cnt   = 0
  show_data= unquote(str(data))
  for p in PATTERN:
    if data.find( p.encode() ) >=0 :
      
      show_data = show_data.replace(p,colored(p,color_enum[(color_cnt% 4)]))
      #hexdata = hexdump.hexdump(data)
      color_cnt +=1
  if( color_cnt ): 
    print("[%s] "% LOG_INFO )
    print (show_data+"\n")

def ssl_hook(message, data):
  p = message["payload"]
  src_addr = socket.inet_ntop(socket.AF_INET, struct.pack(">I", p["src_addr"]))
  dst_addr = socket.inet_ntop(socket.AF_INET, struct.pack(">I", p["dst_addr"]))
  #print("SSL Session: " + p["ssl_session_id"])
  #print("[%s] %s:%d --> %s:%d" % (p["function"], src_addr, p["src_port"], dst_addr, p["dst_port"]))
  LOG_INFO = "SSL Session: " + p["ssl_session_id"] + "\n"
  LOG_INFO += "[%s] %s:%d --> %s:%d" % (p["function"], src_addr, p["src_port"], dst_addr, p["dst_port"])
  log_pcap(pcap_file, p["ssl_session_id"], p["function"], p["src_addr"], p["src_port"], p["dst_addr"], p["dst_port"], data)
  dlog_message(data, LOG_INFO)

def on_message(message, data):
  if message["type"] == "error":
    os.kill(os.getpid(), signal.SIGTERM)
    return
  if len(data) == 0: return

  if(message['payload']['function'] =='SSL_read' or message['payload']['function']  =='SSL_write'):
    ssl_hook(message,data)

  if(message['payload']['function'] ==''):
    pass


def pcap_init():
  pcap_file = open(pcap, "wb", 0)
  for writes in (
          ("=I", 0xa1b2c3d4),     # Magic number
          ("=H", 2),              # Major version number
          ("=H", 4),              # Minor version number
          ("=i", time.timezone),  # GMT to local correction
          ("=I", 0),              # Accuracy of timestamps
          ("=I", 65535),          # Max length of captured packets
          ("=I", 228)):           # Data link type (LINKTYPE_IPV4)
      pcap_file.write(struct.pack(writes[0], writes[1]))
  return pcap_file 

if __name__ == "__main__":
  # pcap logging
  print("[+] START")
  print("[I] Press Ctrl+C to stop logging.")
  pcap_file = pcap_init()
  session = frida.get_usb_device().attach(application)
  script = session.create_script(_FRIDA_SCRIPT)
  script.on('message', on_message)
  script.load()

  try:
      sys.stdin.read()
  except KeyboardInterrupt:
      pass
  session.detach()
  pcap_file.close()
  exit(0)