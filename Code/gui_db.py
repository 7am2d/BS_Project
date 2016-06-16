from sqlalchemy import create_engine
from sqlalchemy.orm import  sessionmaker
import database as db

class Dina():
    def __init__(self):
        engine = create_engine('sqlite:////root/BS_sys/bs_dbi.db')
        self.Session = sessionmaker(bind= engine)

    def pc_list(self, user_id):
        session = self.Session()
        res = session.query(db.PC).filter(db.PC.user_id == user_id).all()
        session.close()
        for i in res:
            print i.pc_id
            print i.mac_address
            print i.osmatch
            print i.family
            print i.pc_uuid
            print i.status
        return res
    
    def scanner_log(self, user_id):
        session = self.Session()
        res = session.query(db.User.user_id).filter(db.User.user_id == user_id)
        r = res.user_id
        session.close()
        return r
    
    def count_reports(self, pc_id):
        session = self.Session()
        sql = session.query(db.Report.report_id, db.Vuln, db.Exploit).filter(db.Report.pc_id == pc_id)
        sql = sql.query(db.Report.report_id == db.Vuln.report_id)
        sql = sql.filter(db.Vuln.vul_id == db.Exploit.vul_id)
        #count = sql.count()
        res = sql.all()
        session.close()
        print res
    
    def vuln_report(self, report_id):
        session = self.Session()
        res = session.query(db.Vuln.vul_oid, db.Vuln.vul_name, db.Vuln.vul_desc, db.Vuln.risk_factor ).filter(db.Vuln.report_id == report_id)
        r = res.all()
        for i in r:
            print i.vul_oid
            print i.vul_name
            print i.vul_desc #here you have to parse the desc to get the fix !!!
            print i.vul_fix
            print i.risk_factor
        session.close()
        return r
    
    def exp_report(self, report_id):
        session = self.Session()
        res = session.query(db.Exploit).filter(db.Exploit.report_id == report_id)
        r = res.all()
        session.close()
        for i in r:
            print i.exploit_id
            print i.exploit_fname
            print i.exploit_desc
            print i.exploit_rank
            print i.exploit_test
        return r
    
    def summ_report(self, report_id):
        session = self.Session()
        qry = session.query(db.Exploit, db.Vuln)
        qry = qry.filter(db.Vuln.report_id == report_id)
        qry = qry.filter(db.Vuln.vul_id == db.Exploit.vul_id)
        res = qry.all()
        session.close()
        for i, j in res:
            print i.exploit_id
            print j.vul_name
            print i.exploit_fname
            print i.exploit_test
        return res
    
    
        
        
        