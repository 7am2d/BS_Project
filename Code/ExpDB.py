from sqlalchemy import create_engine

class Exp_Details:
    def __init__(self):
        self.engine = create_engine("postgresql+psycopg2://postgres:toor@127.0.0.1/msf3")
        self.connection = self.engine.connect()
    
    def queryf(self, cve):
        query = """select md.id, md.fullname, md.rank, md.description 
                from module_details as md,module_refs as mr 
                where mr.name='"""+ cve+ "' and mr.detail_id = md.id"
        result = self.connection.execute(query)
        if result.rowcount==0:
            return 0
        else:
            return result.fetchall()
    
    def fullexp(self, resultL):
        x = "None"
        resultL = self.queryf()
        for row in resultL:
            print row['id']  
            print row['fullname']
            print row['rank']
            print row['description']
            
            
        resultL.close()
        return x
        
    def expList(self,cves):
        lists =[]
        for c in cves:
            print c +"\t::\n"
            r= self.queryf(c)
            ex = self.fnamefinder(r)
            if ex != "None":
                lists.append(ex) 
        return lists
    
    

    
