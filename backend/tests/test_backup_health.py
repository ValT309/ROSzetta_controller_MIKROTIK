import importlib.util
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone, timedelta
import sys, types, unittest
from sqlalchemy import create_engine, Integer, String, DateTime, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

class Base(DeclarativeBase): pass
class Device(Base):
    __tablename__='devices'; id:Mapped[int]=mapped_column(primary_key=True); name:Mapped[str]=mapped_column(String); identity:Mapped[str|None]=mapped_column(String)
class Backup(Base):
    __tablename__='backups'; id:Mapped[int]=mapped_column(primary_key=True); device_id:Mapped[int]=mapped_column(Integer); filename:Mapped[str]=mapped_column(String); fmt:Mapped[str]=mapped_column(String); size:Mapped[int]=mapped_column(Integer); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True)); content:Mapped[bytes]=mapped_column(LargeBinary)
class Alert(Base):
    __tablename__='alerts'; id:Mapped[int]=mapped_column(primary_key=True); source:Mapped[str]=mapped_column(String); category:Mapped[str]=mapped_column(String); created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
engine=create_engine('sqlite://'); Session=sessionmaker(bind=engine)
current=datetime(2026,11,19,12,tzinfo=timezone.utc)
alerts=[]
def add_alert(db,**kw):
    alerts.append(kw);db.add(Alert(source=kw['source'],category=kw['category'],created_at=current));db.commit()
for n in ('health_test','health_test.models','health_test.services'):
    m=types.ModuleType(n);m.__path__=[];sys.modules[n]=m
for n,attrs in {'models.backup':{'DeviceBackup':Backup},'models.device':{'Device':Device},'models.alert':{'Alert':Alert},'services.events':{'add_alert':add_alert}}.items():
    m=types.ModuleType('health_test.'+n);m.__dict__.update(attrs);sys.modules[m.__name__]=m
spec=importlib.util.spec_from_file_location('health_test.services.backup_health',Path(__file__).resolve().parents[1]/'app/services/backup_health.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class HealthTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine);Base.metadata.create_all(engine);alerts.clear();self.db=Session();self.db.add_all([Device(id=1,name='A'),Device(id=2,name='B')]);self.db.commit()
    def tearDown(self):self.db.close()
    def add(self,base,age=0,text=b'/ip address\nadd address=1.2.3.4',device=1,binary=True):
        if binary:self.db.add(Backup(device_id=device,filename=base+'.backup',fmt='binary',size=3,content=b'bin',created_at=current-timedelta(hours=age)))
        t=Backup(device_id=device,filename=base+'.rsc',fmt='text',size=len(text),content=text,created_at=current-timedelta(hours=age));self.db.add(t);self.db.commit();return t.id
    def test_missing(self): self.assertEqual(h.inventory(self.db,current)['devices']['1']['status'],'missing')
    def test_stale_and_fresh(self):
        self.add('old',49);self.add('new',1,device=2);r=h.inventory(self.db,current)['devices'];self.assertEqual((r['1']['status'],r['2']['status']),('stale','fresh'))
    def test_incomplete(self):
        self.add('old',60);self.add('new',0,binary=False);self.assertEqual(h.inventory(self.db,current)['devices']['1']['status'],'stale')
    def test_duplicate(self):
        self.add('same');self.add('same');self.assertEqual(h.inventory(self.db,current)['devices']['1']['status'],'missing')
    def test_header(self):
        a=b'# 2026-11-18 10:00:00 by RouterOS 7.23\r\n# software id = X\r\n/ip dns\r\n';b=b'# 2026-11-19 10:00:00 by RouterOS 7.23\n# software id = X\n/ip dns\n';self.assertEqual(h.normalized_export(a),h.normalized_export(b));self.assertNotEqual(h.normalized_export(a),h.normalized_export(b.replace(b'7.23',b'7.24')))
    def test_order(self):self.assertNotEqual(h.normalized_export(b'/ip firewall filter\nadd action=accept\nadd action=drop'),h.normalized_export(b'/ip firewall filter\nadd action=drop\nadd action=accept'))
    def test_first(self):self.assertFalse(h.inspect_new_pair(self.db,1,self.add('first')));self.assertFalse(alerts)
    def test_changed(self):
        self.add('old',2);i=self.add('new',text=b'/ppp secret\nadd password=TEST_SECRET');self.assertTrue(h.inspect_new_pair(self.db,1,i));self.assertNotIn('TEST_SECRET',str(alerts))
    def test_same(self):self.add('old',1);self.assertFalse(h.inspect_new_pair(self.db,1,self.add('new')));self.assertFalse(alerts)
    def test_stale_alert_dedup(self):self.assertTrue(h.warn_stale(self.db,current));self.assertFalse(h.warn_stale(self.db,current));self.assertEqual(len(alerts),1)
    def test_no_stale_alert(self):self.add('a');self.add('b',device=2);self.assertFalse(h.warn_stale(self.db,current));self.assertFalse(alerts)
if __name__=='__main__':unittest.main()
