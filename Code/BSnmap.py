#!/usr/bin/env python

import nmap

class bsnmap():
    
    def __init__(self,IP):
        self.IP         = IP
        self.res_list   =""
        self.portscan = nmap.PortScanner()
        self.res_list= ""
        self.hostScan()
        
    def hostScan(self):
        self.res_list=self.portscan.scan(self.IP,'22-446', arguments = '-O -v')
        
    def host_status(self):
        state = self.portscan[self.IP].state()
        return state
    
    def host_name(self):
        hostname = self.portscan[self.IP].hostname()
        return hostname    
    
    def host_mac (self):
        mac = self.res_list['scan'][self.IP]['addresses']['mac']
        return mac
    
    def os_match (self):
        osi = self.res_list['scan'][self.IP]['osmatch'][0]['name']
        return osi
    
    def os_family (self):
        os_family = self.res_list['scan'][self.IP]['osclass'][0]['osfamily']
        return os_family
    
    def os_vendor (self):
        os_vendor = self.res_list['scan'][self.IP]['osclass'][0]['vendor']
        return os_vendor
    def printInfo(self):
        print   "Status    :\t"+self.host_status()
        print   "MAC       :\t"+self.host_mac()
        print   "Name      :\t"+self.host_name()
        print   "Family    :\t"+self.os_family()
        print   "OS match  :\t"+self.os_match()
        print   "Vendor    :\t"+self.os_vendor()
        
def main():
    ip = '192.168.127.5'
    n = bsnmap(ip)
    #n.hostScan()
    print   n.host_status()
    print   n.host_mac()
    print   n.host_name()
    print   n.os_family()
    print   n.os_match()
    print   n.os_vendor()
    n.printInfo()   


if __name__ == "__main__":
    main()