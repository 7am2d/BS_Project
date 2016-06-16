#!/usr/bin/env python

import xml.etree.ElementTree as ET
import shlex



class bsxml:
	
	
	def file (self, f):
		self.xmlfile = f
		self.tree = ET.parse(self.xmlfile)
		self.roots = self.tree.getroot()

		
	def xmlprint (self):
		root= self.roots
		print root.get('format_id') ##test1
		#status
		print "STATUS" + "\t" + root.find("./report/scan_run_status").text
		# filters 
		print "FILTERS"
		for f in root.iter('filter'):
				print f.text
		# taskname
		print "TASK Name"
		tasks=root.findall("./report/task/name")
		for t in tasks:
				print t.text
		#  ports
		print "PORTS"
		ports = root.findall("./report/ports/port")
		for port in ports:
			print port.text + '\t' + port.find("threat").text
		# results
		print "RESULTS"
		results = root.findall("./report/results/result")
		for result in results:
			print "\t"+result.find('host').text +'\t' +result.find('port').text +'\t'+ result.find('nvt').get("oid")+'\t'+result.find('host').text
		# result_count
		print "result_count"
		rcount=root.find("./report/result_count")
		print rcount.text
		#host_details
		hdetails=root.findall("./report/host/detail")
		for detail in hdetails:
			print detail.find("name").text + "\t" + detail.find("value").text	
		
		# times!
			# scan-time
		print "scan start time \t"+ root.find("./report/scan_start").text
		print "scan end time \t"+ root.find("./report/scan_end").text
			#host-time
		print "host start time \t"+ root.find("./report/host_start").text
		print "host end time \t"+ root.find("./report/host_end").text
		
			
	def cvefinder(self):
		CVEs=""
		cvel = []
		root= self.roots
		results = root.findall("./report/results/result/nvt")
		for result in results:
			CCVE 	=result.find('cve').text
			if CCVE !=  "NOCVE" and CCVE != None:
				CVEs += str(CCVE) +", " 	
			else:
				continue
		lexer = shlex.split(CVEs)
		for token in lexer:
			cvel.append(repr(token)[1:-2])
		return cvel
	
	def bidfinder(self):
		BIDs=""
		bidl = []
		root= self.roots
		results = root.findall("./report/results/result/nvt")
		for result in results:
			BBID 	=result.find('bid').text
			if BBID !=  "NOCVE" and BBID != None:
				BIDs += str(BBID) +", " 	
			else:
				continue
		lexer = shlex.split(BIDs)
		for token in lexer:
			bidl.append(repr(token)[1:-2])
		return bidl
		
	def xreffinder(self):
		XRs=""
		xrefl = []
		root= self.roots
		results = root.findall("./report/results/result/nvt")
		for result in results:
			XREF 	=result.find('xref').text
			if XREF !=  "NOXREF" and XREF != None:
				XRs += str(XREF) +", " 	
			else:
				continue
		lexer = shlex.split(XRs)
		for token in lexer:
			xrefl.append(repr(token)[1:-2])
		print xrefl
		return xrefl
	
	def vulCount (self):
		res = self.roots.find("./report/result_count/full").text
		return res
			
	def getNVTs(self):
		nvtL= []
		results = self.roots.findall("./report/results/result/nvt")
		for result in results:
			nvt= []
			nvt.append(result.get("oid")) 
			nvt.append(result.find('name').text)
			nvt.append(result.find('risk_factor').text)
			nvt.append(result.find('cve').text)
			nvt.append(result.find('bid').text)
			nvt.append(result.find('xref').text)
			nvtL.append(nvt)
		print nvtL
		results = self.roots.findall("./report/results/result")
		i=0
		for result in results:	
			#print result.find('description').text
			r = result.find('description').text
			if r.find('Fix:') == -1:
				r=""
			else:
				r= r[r.find('Fix:'):]
			nvtL[i].append(result.find('description').text)
			nvtL[i].append(r)
			i=i+1
		#print nvtL[4][6]
		return nvtL	
	
		
def main():
	filexmll='/root/BS_Sys/root/xml/192.168.127.5-2013-06-24 09:49.xml'
	parser = bsxml()
	parser.file(filexmll)
	c = parser.cvefinder()
	for i in c:
		print i
	print parser.vulCount()
	#parser.getNVTs()
	#cves= parser.cvefinder()
	#parser.xmlprint()
	
	
if __name__ == "__main__":
	main()
