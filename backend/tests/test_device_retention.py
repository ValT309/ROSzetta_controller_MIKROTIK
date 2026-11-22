"""Test actual rotation logic with isolated SQLite models; no real device calls."""
import unittest, types, sys, importlib.util
from pathlib import Path
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, Integer, String, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from pydantic import BaseModel
class Base(DeclarativeBase): pass
class DeviceBackup(Base):
    __tablename__='backups'
    id:Mapped[int]=mapped_column(primary_key=True)
    device_id:Mapped[int]=mapped_column(Integer)
    filename:Mapped[str]=mapped_column(String)
    fmt:Mapped[str]=mapped_column(String)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True))
class Device: pass
class User: pass
class BackupOut(BaseModel): pass
engine=create_engine('sqlite://');SessionLocal=sessionmaker(bind=engine)
def get_db(): pass
cfg={}
modules={
 'core.db':{'get_db':get_db}, 'core.security':{'decrypt_secret':lambda x:x},
 'models.backup':{'DeviceBackup':DeviceBackup}, 'models.device':{'Device':Device}, 'models.user':{'User':User},
 'schemas.backup':{'BackupOut':BackupOut}, 'services.routeros.backup':{'create_and_download_backup':lambda:None},
 'services.routeros.client':{'RouterOSCredentials':type('RouterOSCredentials',(),{}),'RouterOSError':RuntimeError},
 'services.backup_ftp_server':{'detect_push_host':lambda:None},'core.config':{'get_settings':lambda:None},
 'api.deps':{'get_current_user':lambda:None,'require_role':lambda *args:lambda:None},
 'services.settings':{'get_settings_dict':lambda db:cfg},
}
for name in ('ret_test','ret_test.core','ret_test.models','ret_test.schemas','ret_test.services','ret_test.services.routeros','ret_test.api','ret_test.api.v1'):
    mod=types.ModuleType(name);mod.__path__=[];sys.modules[name]=mod
for name,attrs in modules.items():
    mod=types.ModuleType('ret_test.'+name);mod.__dict__.update(attrs);sys.modules[mod.__name__]=mod
spec=importlib.util.spec_from_file_location('ret_test.api.v1.backups',Path(__file__).resolve().parents[1]/'app/api/v1/backups.py'); b=importlib.util.module_from_spec(spec);sys.modules[spec.name]=b;spec.loader.exec_module(b)
class TestRotation(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine);Base.metadata.create_all(engine);cfg.clear();self.db=SessionLocal()
        for n in range(12):
            for suffix,fmt in [('backup','binary'),('rsc','text')]:
                self.db.add(DeviceBackup(device_id=1,filename=f'pair{n}.{suffix}',fmt=fmt,created_at=datetime.now(timezone.utc)-timedelta(days=n+4)))
        self.db.add(DeviceBackup(device_id=2,filename='other.backup',fmt='binary',created_at=datetime.now(timezone.utc)))
        self.db.commit()
    def tearDown(self):self.db.close()
    def files(self):return {r.filename for r in self.db.query(DeviceBackup).filter_by(device_id=1).all()}
    def test_default(self):
        b._rotate(self.db,1);self.assertEqual(len(self.files()),20);self.assertIn('pair0.backup',self.files());self.assertEqual(self.db.query(DeviceBackup).filter_by(device_id=2).count(),1)
    def test_count(self):
        cfg['backup_retention']={'pairs':2,'days':0};b._rotate(self.db,1);self.assertEqual(self.files(),{'pair0.backup','pair0.rsc','pair1.backup','pair1.rsc'})
    def test_age_keep_latest(self):
        cfg['backup_retention']={'pairs':10,'days':1};b._rotate(self.db,1);self.assertEqual(self.files(),{'pair0.backup','pair0.rsc'})
    def test_invalid_policy(self):
        cfg['backup_retention']={'pairs':'bad','days':False};self.assertEqual(b.retention_policy(self.db),{'pairs':10,'days':0})
if __name__=='__main__':unittest.main()
