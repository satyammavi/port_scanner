#!/usr/bin/python3

from argparse import ArgumentParser
import socket
from threading import Thread 
from time import time 

""" simple port scanner in python3 
     python3 portscanner.py -s 1 -e 65535 -t 1000 127.0.0.1

    """

print("---------------------------------------------------------------------------------------------------------------------------------------------")
print("                                                         Port scannner                                                                       ")
print("---------------------------------------------------------------------------------------------------------------------------------------------") 
print()
print()
print('''
      
$$$$$$$\                       $$\                                                                      
$$  __$$\                      $$ |                                                                     
$$ |  $$ | $$$$$$\   $$$$$$\ $$$$$$\          $$$$$$$\  $$$$$$$\ $$$$$$\  $$$$$$$\   $$$$$$\   $$$$$$\ 
$$$$$$$  |$$  __$$\ $$  __$$\\_$$  _|        $$  _____|$$  _____|\____$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$  ____/ $$ /  $$ |$$ |  \__| $$ |          \$$$$$$\  $$ /      $$$$$$$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|
$$ |      $$ |  $$ |$$ |       $$ |$$\        \____$$\ $$ |     $$  __$$ |$$ |  $$ |$$   ____|$$ |       
$$ |      \$$$$$$  |$$ |       \$$$$  |      $$$$$$$  |\$$$$$$$\\$$$$$$$ |$$ |  $$ |\$$$$$$$\ $$ |      
\__|       \______/ \__|        \____/       \_______/  \_______|\_______|\__|  \__| \_______|\__|
|                                                                                                |
|----------------------------------------------satyam mavi--------------------------------------|''')

print("\nGithub: https://github.com/satyammavi/port_scanner\n")

open_ports = []

def prepare_args():
	
	parser = ArgumentParser(description="Python Based fast port scanner ",usage="%(prog)s 192.168.1.106",epilog="Example - %(prog)s -s 20 -e 40000 -t 500 -V 192.168.1.106")
	parser.add_argument(metavar="IPv4",dest="ip",help="Host ip address")
	parser.add_argument("-s","--start",dest="start",metavar="",type=int,help="starting port default starting port is 1 ",default=1)  
	parser.add_argument("-e","--end",dest="end",metavar="",type=int,help="ending port",default=65535)
	parser.add_argument("-t","--threads",dest="threads",metavar="",type=int,help="threads to use default thread are use 1000 ",default=1000)
	parser.add_argument("-V","--verbose",dest="verbose",action="store_true",help="verbose output")
	parser.add_argument("-v","--version",action="version",version="%(prog)s 1.0",help="display version")
	parser.add_argument("-o","--output",dest="output_file",help="output file to satore the result")
	args = parser.parse_args()
	return args 	

def prepare_ports(start:int,end:int):
	"""genrator function and generator are also use loop

	     arguments:
	       start(int) - enter starting port
	       end(int) - eneter ending port
	""" 
	for port in range(start,end+1):
	    yield port      

def scan_port():
	""" scan a port
	"""

	while True:
		try:
			s = socket.socket()
			s.settimeout(1)
			port = next(ports)
			s.connect((arguments.ip,port))
			open_ports.append(port)
			if arguments.verbose:
				print(f"\r{open_ports}",end="")
		except (ConnectionRefusedError,socket.timeout):
		    continue 
		except StopIteration:
		    break

def write_output_to_file(output_file):
	with open(output_file,'w') as file:
		file.write("open port found:\n")
		for port in open_ports:
			file.write(str(port) + "\n")


def prepare_threads(threads:int):
	"""create and start and join threads

	    argument:
	      threads(int) - number of threads to use
	"""      

	thread_list = []
	for _ in range(threads+1):
	    thread_list.append(Thread(target=scan_port))

	for thread in thread_list:
	    thread.start() 

	for thread in thread_list:
	    thread.join()       

if __name__ == "__main__":
	arguments = prepare_args()
	ports = prepare_ports(arguments.start,arguments.end)
	start_time = time()
	prepare_threads(arguments.threads)
	end_time = time()
	if arguments.verbose:
	    print()
	print(f"open port found - {open_ports}")
	print()
	print(f"Time taken - {round(end_time-start_time,2)}")

	if arguments.output_file:
		write_output_to_file(arguments.output_file)

print()
print("----Result---")


