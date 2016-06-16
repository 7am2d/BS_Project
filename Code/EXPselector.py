from sqlalchemy import create_engine

class pgselect:
    cvel = []
    def __init__(self):
        self.engine = create_engine("postgresql+psycopg2://postgres:toor@127.0.0.1/msf3")
        self.connection = self.engine.connect()
    
    def queryf(self, cve):
        query = """select md.name, md.fullname, md.rank, md.description 
                from module_details as md,module_refs as mr 
                where mr.name='"""+ cve+ "' and mr.detail_id = md.id"
        result = self.connection.execute(query)
        # checks if there is a result or not!
        '''
        if result.rowcount==0:
            print "ZERO RESULTS!"
        
        # this prints the keys of the result! {attributes}
        for k in result.keys():
            print k
        '''
            
        return result
    
    def print1 (self, resultL):       
        # This is the other!
        for row in resultL:
            print "name:: ", row['name']
            print "Fname: ", row['fullname']
            print "Rank:: ", row['rank']
            print "Desc.: ", row['description']
            
        print "--------------\n--------------\n"
        resultL.close()
        
    def print2 (self, resultL): 
        # the following block is better that the other!
        i=0
        for item in resultL.fetchall():
            print "!!! Names !!! "
            print item[0]
            print 'name' + str(i) ,item[i][0]
            print "-----------------"
            print "!!! First Name !!! "
            print item[1]
            print 'Fname' + str(i) ,item[i][1]
            print "-------------------"
            print "!!! Rank !!!"
            print item[2]
            print "Rank"+str(i), item[i][2]
            print "-----------------------"
            print "!!! Description !!!"
            print item[3]
            print "Desc. "+str(i), item[i][3]
        print "--------------\n--------------\n"
        resultL.close()
    
    def fnamefinder(self, resultL):
        x = "None"
        for row in resultL:
            x = row['fullname']
            
        resultL.close()
        return x
    
    def expList(self,cves):
        lists =[]
        for c in cves:
            #print c +"\t::\n"
            r= self.queryf(c)
            ex = self.fnamefinder(r)
            if ex != "None":
                lists.append(ex) 
        return lists

        




def main():
    cves=['CVE-2001-0797', 'CVE-2001-0797', 'CVE-2008-4114', 'CVE-2010-0020', 'CVE-2010-0020']
    tst=pgselect()
    
    myExpList = tst.expList(cves)
    
    for r in myExpList:
        print r
        
    '''
    for c in cves:
        #print c +"\t::\n"
        r= tst.queryf(c)
        print tst.fnamefinder(r)
        r= tst.queryf(c)
        tst.print1(r)
    
    for c in cves:
        r= tst.queryf(c)
        print tst.fnamefinder(r)
    '''
if __name__ == "__main__":
    main()
