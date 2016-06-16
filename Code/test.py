import nmap 
from BSnmap import bsnmap

while True:
    ip = raw_input("Add target IP:")
    parts = ip.split('.')            
    if (len(parts) == 4) and (all(0 <= int(part) < 256 for part in parts)):
        break
    else:
        print "invalid Target IP.!"
print "Wait for Checking..."
tar_ip = ""

while True:
    try :
        nm =bsnmap (ip)
        nm.printInfo()
        tar_ip = ip
        mac = nm.host_mac()
        family= nm.os_family()
        os_match =nm.os_match()
        break
    except :
        print "Host IP "+ip+ "is down!!!"
print "Your target IP : " + tar_ip    