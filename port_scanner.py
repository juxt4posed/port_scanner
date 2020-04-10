#!/bin/python3

from datetime import datetime as dt
import sys
import socket
lower_port = 1
higher_port = 2


def higher():
	global higher_port
	higher_port = input("please set the highest port you want to scan: ") #set the highest port to scan
	if higher_port.isdigit():
		if int(higher_port) > 65535:
			print(higher_port + " is higher than 65535, please choose a port betwwen 1-65535")
			higher()
		elif int(higher_port) <1:
			print(higher_port + " is less than 1, please choose a port between 1 and 65535")
			higher()
	else:
		print("\nsorry, we only accept intergers, please try again!\n")
		higher()
def lower():
	global lower_port
	lower_port = input("please set the lowest port you want to scan: ") #sets the bottom port to scan
	if lower_port.isdigit():
		if int(lower_port) <1:
			print(lower_port + " is less than 1, please choose a port between 1 and 65535")
			lower()
		elif int(lower_port) > 65535:
			print(lower_port + " is higher than 65535, please choose a port betwwen 1-65535")
			lower()
	else:
		print("\nunfortunately, we only accept intergers, please try again!\n")
		lower()


#define our target
if len(sys.argv) == 2:
	target = socket.gethostbyname(sys.argv[1]) # same as $1 in bash, translate hostname to ipv4
else:
	print("invalid amount of arguments")
	print(" syntax: ./portscanner.py (hostname)")	

#add a pretty banner
print("-"*50)
print("scanning target: " + target)
print("-"*50)
lower()
higher()
start_time = dt.now()
print("-"*50)
print("\n")
print("Time Started: " + str(start_time))
print("\n")
print("-"*50)
try:
	print(lower_port)
	print(higher_port)
	for port in range (int(lower_port),int(higher_port)):
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM) #opens the socket at port
		socket.setdefaulttimeout(1) #sets the default time out
		result=s.connect_ex((target,port)) #returns an error indicator
		if result ==0:
			print("\nport {} is open!".format(port))
		s.close()
	print("\nscan complete\n")
	end_time =dt.now()
	total_time = end_time - start_time
	print("the scan took: " + str(total_time.total_seconds()) + "seconds to complete")
			

except KeyboardInterrupt:
	print("\nexiting program")
	sys.exit()
except socket.gaierror:
	print("\ncouldnt resolve host name")
	sys.exit()
except socket.error:
	print ("\n Couldn't connect to server")
	sys.exit()
