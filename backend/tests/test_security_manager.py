import os,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
from hashlib import sha256
import base64
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
os.environ.setdefault('DATABASE_URL','sqlite://')
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.services import security_manager as m
from app.models.device import Device
from app.core.db import Base
# The boolean converter is pure; no RouterOS client dependency needed here.
client=types.ModuleType('app.services.routeros.client');client.RouterOSError=RuntimeError;client.routeros_session=None
class Key:
    def asbytes(self):return b'test-key'
class Tests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite://')
        Base.metadata.create_all(self.engine,tables=[Device.__table__,m.SecurityPreferences.__table__,m.SecuritySnapshot.__table__])
        self.db=Session(self.engine);self.d=Device(name='test',host='192.0.2.1',username='abc',password_enc='not-real');self.db.add(self.d);self.db.commit()
    def tearDown(self):self.db.close();self.engine.dispose()
    def test_fingerprint(self):self.assertEqual(m.fingerprint(Key()),'SHA256:'+base64.b64encode(sha256(b'test-key').digest()).decode().rstrip('='))
    def test_equal(self):m.compare_key('a',['a'],'a',False)
    def test_first(self):m.compare_key('a',[],'a',False)
    def test_changed(self):self.assertRaises(ValueError,m.compare_key,'b',['a'],'b',False)
    def test_rescan_changed(self):self.assertRaises(ValueError,m.compare_key,'b',['a'],'a',True)
    def test_explicit_replace(self):m.compare_key('b',['a'],'b',True)
    def test_default(self):self.assertEqual(m.backup_options(self.db,self.d),{'backup_mode':'auto','trusted_key':None})
    def test_persistence(self):
        row=m.prefs(self.db,self.d,True);row.backup_mode='pull';self.db.commit();self.db.expire_all();self.assertEqual(m.backup_options(self.db,self.d)['backup_mode'],'pull')
    def test_address_changed(self):
        row=m.prefs(self.db,self.d,True);row.backup_mode='push';self.db.commit();self.d.host='192.0.2.2';self.db.commit();self.assertEqual(m.backup_options(self.db,self.d)['backup_mode'],'auto');self.assertEqual(m.prefs(self.db,self.d,True).host,'192.0.2.2')
    def test_legacy(self):
        with patch.object(m,'legacy_keys',return_value=[Key()]):self.assertEqual(m.trust_status(self.db,self.d)['source'],'known_hosts')
    def test_db_precedence(self):
        r=m.prefs(self.db,self.d,True);r.public_key='x';r.key_type='ssh-rsa';self.db.commit()
        with patch.object(m,'db_key',return_value=Key()),patch.object(m,'legacy_keys',side_effect=AssertionError):self.assertEqual(m.trust_status(self.db,self.d)['source'],'database')
    def test_findings(self):
        with patch.dict(sys.modules,{'app.services.routeros.client':client}):
            f=m.findings({'services':{'status':'ok','rows':[{'name':'telnet','disabled':False,'address':''},{'name':'ftp','disabled':False,'dynamic':True}]}})
        self.assertIn('telnet',[r['code'] for r in f]);self.assertNotIn('ftp',[r['code'] for r in f])
if __name__=='__main__':unittest.main()
