import datetime
import os
from termcolor import colored

START_TIME=int(datetime.datetime.now().minute)

def printBanner():
 cmd="figlet -w 100 'DDOS DETECTOR'"
 returned_value=os.system(cmd)

