import pyshark
import time
import datetime
import constant
from termcolor import colored
import os
import sys

cap = pyshark.LiveCapture(interface='eth0')
cap.sniff(packet_count=10)
constant.printBanner()
print(colored('Src_address\t'+'Src_port\t'+'Dest_address\t'+'Dest_port\t'+'PROTOCOL\t'+'Time\t','blue'))

def curr_time():
 pre_time=datetime.datetime.now()
 return int(pre_time.minute)

def writeToFile(value):
 f = open("demofile2.txt", "w")
 f.write(value)
 f.close()

def readFromFile():
 f=open("demofile2.txt", "r")
 contents =f.read()
 return int(contents)

def set_no_of_request_in_min(value):
 f=open("reqInMin.txt","w")
 f.write(value)
 f.close

def get_no_of_request_in_min():
 f=open("reqInMin.txt","r")
 contents=f.read()
 return int(contents)

def check_ddos(value):
 if value>7000:
  print("DDOS FOUND")
  print(colored("No of request in a min:"+str(get_no_of_request_in_min()),'red'))
 else:
  print(colored("No of request in a min:"+str(get_no_of_request_in_min()),'green'))
  

def print_conversation_header(pkt):  
    try:
       if(pkt.ip.dst==sys.argv[1]):
           protocol =  pkt.transport_layer
           src_addr = pkt.ip.src
           src_port = pkt[pkt.transport_layer].srcport
           dst_addr = pkt.ip.dst
           dst_port = pkt[pkt.transport_layer].dstport
           tme=curr_time()-constant.START_TIME
           if tme%2==0:
            if readFromFile()==2:
             check_ddos(get_no_of_request_in_min())
             print("-------------------------------------------------------------------------------------------------") 
             print('%s\t%s\t\t%s\t%s\t\t%s\t\t%s' % (src_addr, src_port, dst_addr, dst_port,protocol,tme))
             set_no_of_request_in_min("1")
             writeToFile("3")

            elif readFromFile()==21:
             print('%s\t%s\t\t%s\t%s\t\t%s\t\t%s' % (src_addr, src_port, dst_addr, dst_port,protocol,tme))
             set_no_of_request_in_min("1")
             writeToFile("3")

            else:
             print('%s\t%s\t\t%s\t%s\t\t%s\t\t%s' % (src_addr, src_port, dst_addr, dst_port,protocol,tme))             
             writeToFile("0")
             set_no_of_request_in_min(str(get_no_of_request_in_min()+1))

           else:
             if readFromFile()==0:
              check_ddos(get_no_of_request_in_min())
              print("-------------------------------------------------------------------------------------------------")
              print('%s\t%s\t\t%s\t%s\t\t%s\t\t%s' % (src_addr, src_port, dst_addr, dst_port,protocol,tme))
              set_no_of_request_in_min("1")
              writeToFile("1")

             else:
              print('%s\t%s\t\t%s\t%s\t\t%s\t\t%s' % (src_addr, src_port, dst_addr, dst_port,protocol,tme))
              writeToFile("2")
              set_no_of_request_in_min(str(get_no_of_request_in_min()+1))

    except AttributeError as e:
        #ignore packets that aren't TCP/UDP or IPv4
        pass
set_no_of_request_in_min("0")
writeToFile("21")
cap.apply_on_packets(print_conversation_header)

