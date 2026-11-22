"""Isolated test harness; no RouterOS calls, production PostgreSQL lock not exercised."""
import unittest, sys, types, importlib.util
from pathlib import Path
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, String, Integer, Boolean, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__='users'; id:Mapped[int]=mapped_column(primary_key=True); role:Mapped[str]=mapped_column(String); is_active:Mapped[bool]=mapped_column(Boolean)
class Device(Base):
    __tablename__='devices'; id:Mapped[int]=mapped_column(primary_key=True); name:Mapped[str]=mapped_column(String); identity:Mapped[str|None]=mapped_column(String); host:Mapped[str]=mapped_column(String); ros_version:Mapped[str]=mapped_column(String)
class DeviceBackup(Base):
    __tablename__='backups'; id:Mapped[int]=mapped_column(primary_key=True); device_id:Mapped[int]=mapped_column(Integer); filename:Mapped[str]=mapped_column(String); fmt:Mapped[str]=mapped_column(String); size:Mapped[int]=mapped_column(Integer); content:Mapped[bytes]=mapped_column(LargeBinary,default=b"12345")
engine=create_engine('sqlite://'); SessionLocal=sessionmaker(bind=engine)
def get_db(): pass
def require_role(*roles): return lambda:None
state={'long-term':{'version':'7.24.1','last_check_ok':True,'last_check':datetime.now(timezone.utc).isoformat()}}
vault=types.SimpleNamespace(is_initialized_cached=lambda:False,is_unlocked=lambda:True)
created=[]
def backup(id,db,user):
    created.append(id)
    for suffix,fmt in [('backup','binary'),('rsc','text')]: db.add(DeviceBackup(device_id=id,filename=f'd{id}.{suffix}',fmt=fmt,size=5))
    db.commit();return db.query(DeviceBackup).filter_by(device_id=id).all()
# Separate namespace avoids pollution of the real app modules.
for n in ('queue_test','queue_test.services','queue_test.core','queue_test.api','queue_test.api.v1','queue_test.models'):
    m=types.ModuleType(n);m.__path__=[];sys.modules[n]=m
for n,fields in {'core.db':locals(), 'api.deps':{'require_role':require_role},'models.user':{'User':User},'models.device':{'Device':Device},'models.backup':{'DeviceBackup':DeviceBackup},'services.firmware_check':{'get_state':lambda db:state},'services.vault':{'vault_service':vault},'api.v1.backups':{'create_backup':backup}}.items():
    m=types.ModuleType('queue_test.'+n);m.__dict__.update({k:fields[k] for k in ('Base','SessionLocal','engine','get_db')} if n=='core.db' else fields);sys.modules['queue_test.'+n]=m
spec=importlib.util.spec_from_file_location('queue_test.services.device_queue',Path(__file__).resolve().parents[1]/'app/services/device_queue.py');q=importlib.util.module_from_spec(spec);sys.modules[spec.name]=q;spec.loader.exec_module(q)
class Tests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine);Base.metadata.create_all(engine);created.clear();self.db=SessionLocal();self.db.add_all([User(id=1,role='operator',is_active=True),User(id=2,role='operator',is_active=True),Device(id=1,name='A',host='a',ros_version='7.9'),Device(id=2,name='B',host='b',ros_version='7.24.1')]);self.db.commit()
    def tearDown(self):self.db.close()
    def user(self,n=1):return self.db.get(User,n)
    def make(self,mode='backup',**kw):return q.create(q.Request(ids=[1,2],mode=mode,interval=0,**kw),self.db,self.user())
    def job(self,id):self.db.expire_all();return self.db.get(q.Job,id)
    def test_version(self): self.assertLess(q.version('7.9'),q.version('7.24.1'));self.assertIsNone(q.version('7.24beta2'))
    def test_catalog(self):self.assertEqual(q.catalog(self.db,self.user())['1']['long-term']['status'],'available')
    def test_stale_catalog(self):self.assertEqual(q.availability('7.9',dict(state['long-term'],last_check='2020-01-01T00:00:00+00:00'))['status'],'unknown')
    def test_backup(self):
        j=self.make();q.work();self.assertEqual(created,[1]);q.work();self.assertEqual(created,[1,2]);self.assertEqual(self.job(j['id']).state,'done')
    def test_check(self):
        j=self.make('check');q.work();q.work();self.assertEqual(self.job(j['id']).entries[0]['detail']['status'],'available');self.assertFalse(created)
    def test_plan_no_execution(self):
        j=self.make('plan');q.work();self.assertEqual(self.job(j['id']).state,'planned');self.assertFalse(created)
    def test_future(self):
        j=self.make(scheduled=datetime.now(timezone.utc)+timedelta(hours=1));q.work();self.assertFalse(created);self.assertEqual(self.job(j['id']).state,'queued')
    def test_stop(self):
        j=self.make();q.work();q.stop(j['id'],self.db,self.user());q.work();self.assertEqual(created,[1]);self.assertEqual(self.job(j['id']).state,'stopped')
    def test_interrupted(self):
        j=self.make();row=self.job(j['id']);row.state='running';row.entries=[dict(row.entries[0],state='running'),row.entries[1]];self.db.commit();q.work();self.assertEqual(self.job(j['id']).state,'interrupted');self.assertFalse(created)
    def test_owner(self):
        j=self.make();self.assertEqual(q.jobs(self.db,self.user(2)),[]);self.assertRaises(q.HTTPException,q.stop,j['id'],self.db,self.user(2))
    def test_changed_host(self):
        j=self.make();d=self.db.get(Device,1);d.host='changed';self.db.commit();q.work();self.assertEqual(self.job(j['id']).state,'failed');self.assertFalse(created)
    def test_invalid_mode(self):self.assertRaises(q.HTTPException,self.make,'internet')
    def test_recurrence(self):
        r=self.make(scheduled=q.now()+timedelta(hours=1),frequency='daily'); sid=r['schedule']['id']; row=self.db.get(q.Schedule,sid);row.due=q.now()-timedelta(days=3);self.db.commit();q.work();q.work();self.db.expire_all();self.assertEqual(created,[1,2]);self.assertEqual(self.db.query(q.Job).count(),1);self.assertGreater(q.utc(self.db.get(q.Schedule,sid).due),q.now())
    def test_month(self):
        d=datetime(2024,1,31,tzinfo=timezone.utc);self.assertEqual(q.advance(d,'monthly',31).day,29);self.assertEqual(q.advance(q.advance(d,'monthly',31),'monthly',31).day,31)
    def test_schedule_owner(self):
        r=self.make(scheduled=q.now()+timedelta(hours=1),frequency='weekly'); sid=r['schedule']['id'];self.assertEqual(q.schedules(self.db,self.user(2)),[]);self.assertRaises(q.HTTPException,q.stop_schedule,sid,self.db,self.user(2));q.stop_schedule(sid,self.db,self.user());self.assertFalse(q.schedules(self.db,self.user())[0]['enabled'])
    def test_recurring_plan_rejected(self):
        self.assertRaises(q.HTTPException,self.make,'plan',scheduled=q.now()+timedelta(hours=1),frequency='daily')
    def test_retry(self):
        j=self.make();q.work();q.stop(j['id'],self.db,self.user());r=q.retry(j['id'],self.db,self.user());self.assertEqual([e['id'] for e in r['entries']],[2]);q.work();self.assertEqual(created,[1,2])
    def test_zip(self):
        import io,zipfile
        j=self.make();q.work();q.work();self.db.expire_all();r=q.archive(j['id'],self.db,self.user());z=zipfile.ZipFile(io.BytesIO(r.body));self.assertEqual(len(z.namelist()),4);self.assertRaises(q.HTTPException,q.archive,j['id'],self.db,self.user(2))
    def test_skip_error(self):
        j=self.make(error_policy='skip');d=self.db.get(Device,1);d.host='changed';self.db.commit();q.work();self.assertEqual(self.job(j['id']).state,'queued');q.work();self.assertEqual(created,[2]);self.assertEqual(self.job(j['id']).state,'failed')
    def test_error_detail_no_secret(self):
        detail, retryable=q.error_detail(q.HTTPException(502,'push backup failed: secret=abc'))
        self.assertTrue(retryable);self.assertNotIn('abc',detail);self.assertIn('FTP',detail)
    def test_retry_known_error(self):
        j=self.make(error_policy='retry',retries=1);module=sys.modules['queue_test.api.v1.backups']; original=module.create_backup
        def bad(id,db,user):raise q.HTTPException(502,'push file failed')
        module.create_backup=bad
        try:
            q.work();row=self.job(j['id']);self.assertEqual(row.entries[0]['state'],'pending');self.assertEqual(row.entries[0]['attempts'],1);row.due=q.now();self.db.commit();q.work();row=self.job(j['id']);self.assertEqual(row.entries[0]['state'],'failed');self.assertEqual(row.state,'queued')
        finally:module.create_backup=original
        q.work();self.assertEqual(created,[2]);self.assertEqual(self.job(j['id']).state,'failed')
    def test_schedule_policy(self):
        r=self.make(error_policy='skip',frequency='daily',scheduled=q.now()+timedelta(hours=1));self.assertEqual(r['schedule']['entries'][0]['error_policy'],'skip')
if __name__=='__main__':unittest.main()
