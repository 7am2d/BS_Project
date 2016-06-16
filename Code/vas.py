#!/usr/bin/python

import subprocess,shlex,time
from datetime import datetime
class bsvas:
    def __init__(self, server="127.0.0.1", usr="talta",Password="toor"):   
        self.host="omp -h "+server+" -u "+usr+" -w "+Password
        self.grep="grep -m 1 "
    
    def rFormat(self, f_id= 3, f_name= 1):
                    
                    formatList = [[0 for x in xrange(2)] for x in xrange(5)]
                    formatList[0][0]=("cpe")
                    formatList[0][1]=("5ceff8ba-1f62-11e1-ab9f-406186ea4fc5")
                    formatList[1][0]=("html")
                    formatList[1][1]=("6c248850-1f62-11e1-b082-406186ea4fc5")
                    formatList[2][0]=("pdf")
                    formatList[2][1]=("a0b5bfb2-1f62-11e1-85db-406186ea4fc5")
                    formatList[3][0]=("txt")
                    formatList[3][1]=("a3810a62-1f62-11e1-9219-406186ea4fc5")
                    formatList[4][0]=("xml")
                    formatList[4][1]=("a994b278-1f62-11e1-96ac-406186ea4fc5")
                    return formatList[f_id][f_name]
    
    def getconf(self, conf_num= 0, conf_name= 1):
                    
                    configList = [[0 for x in xrange(2)] for x in xrange(4)] 
                    configList[0][0]=("Full and fast")
                    configList[0][1]=("daba56c8-73ec-11df-a475-002264764cea")
                    configList[1][0]=("Full and fast ultimate")
                    configList[1][1]=("698f691e-7489-11df-9d8c-002264764cea")
                    configList[2][0]=("Full and very deep")
                    configList[2][1]=("708f25c4-7489-11df-8094-002264764cea")
                    configList[3][0]=("Full and very deep ultimate")
                    configList[3][1]=("74db13d6-7489-11df-91b9-002264764cea")
                    return configList[conf_num][conf_name]   
  
    def execom(self, rawcmd,rawcmd2="",outt=subprocess.PIPE,inn=subprocess.PIPE):
        cmd = shlex.split(rawcmd)
        output=subprocess.Popen(cmd,stdin=inn,stdout=outt,stderr=subprocess.STDOUT)
        if rawcmd2 !="":
            return self.execom(rawcmd2,inn=output.stdout)
        retVal = output.communicate()[0]
        return retVal
        
    def checkTarget(self, tar_ip):
                    self.tar_ip = tar_ip
                    cmd =self.host+" --get-targets"
                    result = self.execom(cmd,self.grep+self.tar_ip) #Get Target ID, Name
                    if result == "":
                            self.crTarget(self.tar_ip) #create New Target
                            print "Create new target IP:\t"+self.tar_ip
                            result = self.execom(cmd,self.grep+self.tar_ip) #Get Target ID, Name
                    else:  
                            print "Target "+tar_ip+" already exist!!"          
                    Tar_id = result[0:36] #Select Target ID
                    print result
                    return Tar_id
                            
    def crTarget(self, tar_ip):
                    self.tar_ip= tar_ip
                    rawCMD=self.host+" --xml=\"<create_target> <name>" + self.tar_ip + "</name> <hosts>" +self.tar_ip + "</hosts> </create_target>\""
                    self.execom(rawCMD)
    
    def CheckTask(self, tar_ip):
                    self.tar_ip= tar_ip
                    connie= self.host + " --get-tasks"
                    result=self.execom(connie,self.grep+self.tar_ip)
                    if result == "":
                            print"Create New Task.... "
                            self.crTask(self.tar_ip)
                            result=self.execom(connie,self.grep+self.tar_ip)
                    else:
                        print "task found!"
                    task_ID=result[0:36]
                    print "Task ID is :\t"+task_ID
                    return task_ID
                    
    def crTask(self, tar_ip, conf_id=1):
                    conf =self.getconf(int(conf_id))
                    self.tar_ip =tar_ip
                    tar_ID=self.checkTarget(self.tar_ip)
                    cmd=self.host + " --xml=\"<create_task> <name>" + self.tar_ip + "</name> <comment>temporary task</comment> <config id='" + conf + "'/> <target id='" +tar_ID + "'/></create_task>\""
                    taskID= self.execom(cmd)
                    return taskID[26:62] 
     
    def startTask(self, task_ID):
                    sconnie = self.host+" --xml=\"<start_task task_id='" + task_ID + "'/>\""
                    result = self.execom(sconnie)
                    report_ID = result[result.find("id>")+3:result.find("id>")+39]
                    print "report ID is:\t" + report_ID
                    self.wait(task_ID)
                    return report_ID
    
    def stopTask(self, task_ID):
                    sconnie = self.host+" --xml=\"<stop_task task_id='" + task_ID + "'/>\""
                    result = self.execom(sconnie)
                    print result
                                   
    def delTask(self, task_ID):
                    sconnie = self.host+" --xml=\"<delete_task task_id='" + task_ID + "'/>\""
                    result = self.execom(sconnie)
                    print result
                                           
    def wait(self, T_ID):
                    cmd = self.host+" --get-tasks"
                    grp ="grep "+T_ID
                    result = self.execom(cmd, grp)
                    resList = result.split()
                    print resList[1:3]
                    while(resList[1] != "Done"):
                            time.sleep(5)
                            result = self.execom(cmd,grp)
                            resList = result.split()
                            print "Detection status:\t", resList[1:3]
    
 
    def getreport(self, report_id,dir,formtype=4):
            formt = self.rFormat(int(formtype))
            xml_name=self.tar_ip+"-"+str(datetime.now())[:16]+"."+self.rFormat(int(formtype),0)
            cmd =self.host + " -R "+report_id+" -f "+formt
            fill=open(dir+xml_name,'w')
            try:
                repp = self.execom(cmd)
                fill.write(repp)
                fill.close()
                print "report", xml_name, "created"
            except IOError:
                print "Error: file openvas_result.txt!!!!!"
    
            return dir+xml_name
                
def main():
    
                IP="192.168.127.5"
                tst= bsvas()
                
                tst.checkTarget(IP)
                t_id= tst.CheckTask(IP)
                r= tst.startTask(t_id)
                print 'R ID is:---------------- ',r
                tst.getreport(r, IP)
                '''
                Tid= tst.crTask(IP)
                print Tid
                tst.startTask(Tid)
                '''
if __name__ =="__main__":
        main()
