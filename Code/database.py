from datetime import datetime
from sqlalchemy import create_engine, ForeignKey
from sqlalchemy import Column, Integer, String ,TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref

engine = create_engine('sqlite:////root/BS_Sys/bs_dbi.db', echo = False)
Base = declarative_base()

class User(Base):
    __tablename__="users"

    user_id = Column(Integer, primary_key =True)
    username = Column(String(50), nullable =False)
    password = Column(String(50), nullable =False)
    full_name = Column(String(50), nullable =True)
    user_dir = Column(String(50), nullable =True, unique =True)

    def __init__(self, username, password, full_name =None, user_dir =None):
        self.username = username
        self.password = password
        self.full_name = full_name
        self.user_dir = user_dir

class PC(Base):
    __tablename__ = "pc"

    pc_id = Column(Integer, primary_key =True)
    mac_address = Column(String(50), nullable = True)
    osmatch = Column(String, nullable = True)
    family = Column(String, nullable= True)
    pc_uuid = Column(String(50), nullable = True)
    status = Column(Integer, nullable = True)

    user_id = Column(Integer, ForeignKey("users.user_id", onupdate = "cascade",
        ondelete = "cascade"))
    user = relationship("User", backref=backref("pc", order_by = user_id))

    def __init__(self, user_id, osmatch= None, family =None, mac_address=None, pc_uuid=None, status=None):
        self.user_id = user_id
        self.osmatch= osmatch
        self.family= family
        self.mac_address = mac_address
        self.pc_uuid = pc_uuid
        self.status = status

class Report(Base):
    __tablename__="reports"

    report_id = Column(Integer, primary_key=True)
    rate = Column(Integer, nullable =True)
    date = Column(TIMESTAMP, default = datetime.now())
    report_uuid = Column(String(50), nullable=True)
    config_id = Column(String(50), nullable=True)
    vul_count = Column(String , nullable = True)
    expl_count = Column(String , nullable = True)
    scan_file = Column(String , nullable = True)
    
    pc_id=Column(Integer, ForeignKey("pc.pc_id", onupdate = "cascade", ondelete
        = "cascade"))
    pc = relationship("PC", backref=backref("reports", order_by = pc_id))

    def __init__(self, pc_id, report_uuid =None, config_id =None, rate= None, vul_count =None, expl_count =None, scan_file =None):
        self.pc_id = pc_id
        self.report_uuid = report_uuid
        self.config_id = config_id
        self.rate = rate
        self.vul_count =vul_count
        self.expl_count =expl_count
        self.scan_file =scan_file


class Vuln(Base):
    __tablename__ = "vulns"

    vul_id = Column(Integer, primary_key =True)
    vul_oid = Column(String(50), nullable =False)
    vul_name = Column(String)
    vul_cve = Column(String)
    vul_bid = Column(String)
    vul_xref = Column(String)
    vul_desc = Column(String)
    vul_fix = Column(String)
    risk_factor = Column(String(20))

    report_id = Column(Integer, ForeignKey("reports.report_id", onupdate=
        "cascade", ondelete = "cascade"))
    report = relationship("Report", backref= backref("vulns", order_by=
        report_id))

    def __init__(self, report_id, vul_oid, vul_name =None, vul_cve =None, vul_bid =None, vul_xref =None, vul_desc =None, vul_fix =None, risk_factor =None):
        self.report_id = report_id
        self.vul_oid = vul_oid
        self.vul_name = vul_name
        self.vul_cve = vul_cve
        self.vul_bid = vul_bid
        self.vul_xref = vul_xref
        self.vul_desc = vul_desc
        self.vul_fix = vul_fix
        self.risk_factor = risk_factor

class Exploit(Base):
    __tablename__ = "exploits"

    exploit_id = Column(Integer, primary_key =True)
    msf_id = Column(String)
    exploit_fname = Column(String)
    exploit_rank = Column(String)
    exploit_desc = Column(String)
    exploit_test = Column(String)
    report_id = Column(String)
    
    vul_id = Column(Integer, ForeignKey("vulns.vul_id", onupdate ="cascade",
        ondelete ="cascade"))
    vul = relationship("Vuln", backref =backref("exploits", order_by= vul_id))

    def __init__(self, report_id, vul_id, msf_id =None, exploit_fname =None, 
                 exploit_rank =None, exploit_desc =None, exploit_test =None):
        self.report_id = report_id
        self.vul_id = vul_id
        self.msf_id = msf_id
        self.exploit_fname = exploit_fname
        self.exploit_rank = exploit_rank
        self.exploit_desc = exploit_desc
        self.exploit_test = exploit_test

Base.metadata.create_all(engine)
