#!/usr/bin/env python


import os
import database as db
from vas import bsvas
from BSnmap import bsnmap
from xml_parsev1 import bsxml
from ExpDB import Exp_Details 
from datetime import datetime
from EXPselector import pgselect  # MSF Database
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from interactive_msf import MsfConsole
from metasploit.msfrpc import MsfRpcError
from db_select import Dina
import db_select

class BSman (bsvas, pgselect, bsxml):
	
	def __init__(self):
		self.name	 = ""
		self.dir 	 = "/root/BS_Sys/"
		self.logfile = ""
		self.tar_ip = ""
		self.id		 = ""
		self.report_id = "100"
		self.report = ""
		try:
			os.mkdir(self.dir)
		except: 
			pass
		self.engine = create_engine('sqlite:////root/BS_Sys/bs_dbi.db', echo=False)
		self.Session = sessionmaker(bind=self.engine)
		
	def crUser(self):
		user = raw_input("New user name: ")
		session = self.Session()
		qry = session.query(db.User).filter(db.User.username == user)
		if qry.count() == 1:
			print "User name already exist!"
			self.crUser()
			return
		passw = raw_input("Password: ")
		uf_name = raw_input("Enter your name: ")
		uDir = self.dir + user + "/"
		new_user = db.User(user, passw, uf_name, uDir)
		session.add(new_user)
		session.commit()
		session.close()
		self.logW ("New " + user + " user created.")
		print "New " + user + " user created."
		try:
			os.mkdir(uDir)
			os.mkdir(uDir + "/xml")
		except:
			pass
		
	def login(self):
		U = raw_input("user Name: ")
		P = raw_input("Password: ")
		session = self.Session()
		qry = session.query(db.User).filter(db.User.username == U).filter(db.User.password == P)
		liss = qry.all()
		if qry.count() == 1:
				self.id 	 = 	str(liss[0].user_id)
				self.name 	 = 	liss[0].full_name
				self.dir 	 = 	liss[0].user_dir
				self.logW("+++++++ User " + U + " login.")
				print "Welcome " + self.name + " your dir is :" + self.dir
		else:
			print "Invalid Username or Password !!!"
			self.login() 
				
	def checkHost(self):
		while True:
			ip = raw_input("Add target IP:")
			parts = ip.split('.')			
			if (len(parts) == 4) and (all(0 <= int(part) < 256 for part in parts)):
				break
			else:
				print "invalid Target IP.!"
		print "Wait for Checking..."
		try :
			nm = bsnmap (ip)
			nm.printInfo()
			self.tar_ip = ip
			mac = nm.host_mac()
			family = nm.os_family()
			os_match = nm.os_match()
		except :
			print "Host IP " + ip + "is down!!!"
			self.checkHost()
			return	
			
		# Database PCs
		session = self.Session()
		qry = session.query(db.PC).filter(db.PC.user_id == self.id).filter(db.PC.mac_address == mac)
		if qry.count() == 1:
			qry.all()[0].osmatch = os_match
			qry.all()[0].family = family
			session.commit()
		else:
			new_pc = db.PC(self.id, os_match, family, mac)
			session.add(new_pc)
			session.commit()
		qry = session.query(db.PC.pc_id).filter(db.PC.user_id == self.id).filter(db.PC.mac_address == mac).first()
		self.pc_id = qry.pc_id
			
		session.close()
		print "____________________"
		print "Your PC ID is:-> " , self.pc_id ,"|"
		print "____________________|\n"
					
	def scan(self):
		vs = bsvas()
		conf_id = raw_input("Select Scan Configuration:\n0-Full and fast.\n1-Full and fast ultimate.\n2-Full and very deep\n3-Full and very deep ultimate.\nSelect Conf ID(Ex:1):")
		task_ID = vs.crTask(self.tar_ip, conf_id)
		self.logW("Start scan tartget Ip: (" + self.tar_ip + ").")
		report_uuid = vs.startTask(task_ID)
		self.report = vs.getreport(report_uuid, self.dir + "xml/")
		forma = raw_input("Select report forma:\n0-CPE. 1-HTML. 2-PDF. 3-TXT. 4-XML.\n-->")
		uReport = vs.getreport(report_uuid, self.dir, forma)
		print "Report Saved at: ", uReport
		self.logW("Host \"" + self.tar_ip + "\" finish Scanning.")
		self.logW("Scanning Report saved at (" + self.report + ").")
		# database
		session = self.Session()
		new_report = db.Report(self.pc_id, report_uuid, conf_id, scan_file=self.report)
		session.add(new_report)
		session.commit()
		qry = session.query(db.Report.report_id).filter(db.Report.report_uuid == report_uuid).first()
		self.report_id = qry.report_id
		session.close()
		
	def xmlParse(self):
		filexmll = self.report
		# filexmll = "Metasploitaple.xml"
		parser = bsxml()
		parser.file(filexmll)
		self.cves = parser.cvefinder()
		print len(self.cves) , " CVEs Found."
		self.vulns_insert(parser.vulCount())
		self.logW(str(len(self.cves)) + " CVEs Found.")
		print self.cves
		
	def db_vuln (self):
		filexmll = self.report
		# filexmll = "xp.xml"
		parser = bsxml()
		parser.file(filexmll)
		# vul table 
		vulL = parser.getNVTs()
		objs = []
		for vlist in vulL:
			dbo = db.Vuln(int(self.report_id), vlist[0], vlist[1], vlist[3], vlist[4], vlist[5], vlist[6], vlist[7], vlist[2])
			objs.append(dbo)
		session = self.Session()
		session.add_all(objs)
		session.commit()
		session.close()
		
	def vulns_insert(self, vul_count):
		session=self.Session()
		res = session.query(db.Report).filter(db.Report.report_id == self.report_id).first()
		res.vul_count = vul_count
		session.commit()
		session.close()
		
	def expls_insert(self, exploit_count):
		session=self.Session()
		res = session.query(db.Report).filter(db.Report.report_id == self.report_id).first()
		res.expl_count = exploit_count
		session.commit()
		session.close()
		
	def expFinder (self):
		expS = pgselect()
		self.expL = expS.expList(self.cves)
		print len(self.expL) , "Exploits Found."
		self.logW(str(len(self.expL)) + "Exploits Found.")
		self.expls_insert(len(self.expL))
		for e in self.expL:
			print e	
		
	def logW(self, log=""):
		n 		 = str(datetime.now())
		logS 	 = n[:19] + "-->\t\t" + log + "\n"
		logfile = open(self.dir + "log.txt", "a+")
		logfile.write(logS)
		logfile.close()	
				
	def expl_insertion(self):
		dbo = Exp_Details()
		session = self.Session()
		res = session.query(db.Vuln.vul_id, db.Vuln.vul_cve).filter(db.Vuln.report_id == self.report_id).filter(db.Vuln.vul_cve != "NOCVE")
		liss = res.all()
		session.close()
		exploit_list = []
		for i in liss:
			x = i.vul_cve.split(", ")
			for r in x :
				tmp = []
				if dbo.queryf(r) != 0:
					tmp = dbo.queryf(r)
					for c in tmp:
						tmpi = []
						tmpi.append(self.report_id)
						tmpi.append(i.vul_id)
						tmpi.append(c.id)
						tmpi.append(c.fullname)
						tmpi.append(c.rank)
						tmpi.append(c.description)
						exploit_list.append(tmpi)
		exploit_objs = []				
		for i in exploit_list:
			obje = db.Exploit(i[0], i[1], i[2], i[3], i[4], i[5])
			exploit_objs.append(obje)
		session.add_all(exploit_objs)
		session.commit()
		session.close()
	
	def msf_interactive (self):
		try:
			m = MsfConsole()
			m.interact('')
		except MsfRpcError, m:
			print str(m)
		
	def samary (self):
		dee = Dina()
		dee.ret_reports(int(self.id))
		report_id = raw_input("Select Report to get Samary Report: ")
		dee.summ_report(report_id)
		
	def control (self):
		while True :
			c = raw_input("select: \n1) create New User.\n2) Login User.\n3) Exit.\n--->")
			if c == "1":
				self.crUser()
				continue
			elif c == "2":
				self.login()
				while True :
						y = raw_input("Select>> \n1) Check target.\n2) Scan Target\n3) Get Reports.\n4) MSF Interactive Console.\n5) Logout\n6) Exit\n--->")
						if y == "1":
							self.checkHost()
						elif y == "2":
							self.checkHost()
							self.scan()
							self.xmlParse()
							self.expFinder()
							self.db_vuln()
							self.expl_insertion()
						elif y == "3":
							self.samary()	
						elif y == "4":
							self.msf_interactive()	
						elif y == "5":
							break
						elif y == "6":
							exit()
						else :
							print "Unknown Command."
							continue
			elif c == "3" :
				exit()
			else:
				print "Unknown Command."
				continue
				
				
				
						
def main():
		man = BSman()
		man.control()
		#man.msf_interactive()
		
		
		
if __name__ == "__main__":
		main()
