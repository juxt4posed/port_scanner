#!/bin/python3

from datetime import datetime as dt
import sys
import socket

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
lower = input("please set the lowest port you want to scan: ") #sets the bottom port to scan
higher = input("please set the highest port you want to scan: ") #set the highest port to scan
start_time = dt.now()
print("-"*50)
print("\n")
print("Time Started: " + str(start_time))
print("\n")
print("-"*50)
try:
	for port in range (int(lower),int(higher)):
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
