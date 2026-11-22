"""Route logic against SQLite and simulated RouterOS; run as a standalone test."""
import os,sys,types,unittest,ssl
from pathlib import Path
from unittest.mock import patch
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from fastapi import HTTPException
os.environ['DATABASE_URL']='sqlite://'
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
# Isolated stubs for network library/decryption, never used in application.
lib=types.ModuleType('librouteros');lib.connect=lambda **kw:None
exc=types.ModuleType('librouteros.exceptions');exc.LibRouterosError=RuntimeError
login=types.ModuleType('librouteros.login');login.plain=lambda *a:None
security=types.ModuleType('app.core.security');security.decrypt_secret=lambda x:'test';security.encrypt_secret=lambda x:'dummy';security.decode_token=lambda x:{}
with patch.dict(sys.modules,{'librouteros':lib,'librouteros.exceptions':exc,'librouteros.login':login,'app.core.security':security}):
    from app.api.v1 import devices as v
    from app.models.device import Device
    from app.core.db import Base
from test_device_management import API

class Routes(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite://')
        Base.metadata.create_all(self.engine,tables=[Device.__table__,v.DeviceManagementEvent.__table__]);self.db=Session(self.engine)
        self.d=Device(id=1,name='old',identity='old',host='192.0.2.1',username='admin',password_enc='dummy',port=8728,use_tls=False,kind='router',group_name='test')
        self.db.add(self.d);self.db.commit();self.user=types.SimpleNamespace(email='test')
        self.api=API();self.api.rows[('ip','service')][1].update(disabled=False,certificate='api-cert',address='10.110.0.109/32')
        self.api.rows[('system','resource')]=[{'version':'7'}];self.connections=[]
    def tearDown(self):self.db.close();self.engine.dispose()
    @contextmanager
    def session(self,creds):
        self.connections.append(creds);yield self.api
    def test_tls_commit(self):
        with patch.object(v,'routeros_session',self.session):
            r=v.management_tls_switch(1,v.TLSConfirmation(fingerprint='a'*64,port=8729),self.db,self.user)
        self.assertEqual((self.d.port,self.d.use_tls,self.d.tls_fingerprint),(8729,True,'a'*64));self.assertEqual(r['fingerprint'],'a'*64)
        self.assertEqual([c.tls_fingerprint for c in self.connections],[None,'a'*64]);self.assertEqual(self.db.query(v.DeviceManagementEvent).one().action,'tls-switch')
    def test_tls_fail_retains_old(self):
        @contextmanager
        def fail(creds):
            if creds.use_tls: raise ssl.SSLError('pin mismatch')
            yield self.api
        with patch.object(v,'routeros_session',fail),self.assertRaises(HTTPException):v.management_tls_switch(1,v.TLSConfirmation(fingerprint='a'*64,port=8729),self.db,self.user)
        self.assertEqual((self.d.port,self.d.use_tls,self.d.tls_fingerprint),(8728,False,None));self.assertEqual(self.db.query(v.DeviceManagementEvent).one().action,'tls-failed')
    def test_wrong_port(self):
        with patch.object(v,'routeros_session',self.session),self.assertRaises(HTTPException):v.management_tls_switch(1,v.TLSConfirmation(fingerprint='a'*64,port=1111),self.db,self.user)
        self.assertEqual(len(self.connections),1);self.assertFalse(self.d.use_tls)
    def test_rename_confirmed(self):
        with patch.object(v,'routeros_session',self.session):v.management_edit(1,v.ManagementEdit(name='new',kind='switch'),self.db,self.user)
        self.assertEqual((self.d.name,self.d.identity,self.d.kind,self.d.group_name),('new','new','switch','test'))
    def test_category_preserves_identity(self):
        v.management_category(v.CategoryBatch(ids=[1],kind='switch'),self.db,self.user)
        self.assertEqual((self.d.id,self.d.kind,self.d.identity,self.d.group_name),(1,'switch','old','test'))
    def test_category_missing_no_partial(self):
        with self.assertRaises(HTTPException):v.management_category(v.CategoryBatch(ids=[1,2],kind='switch'),self.db,self.user)
        self.assertEqual(self.d.kind,'router')
    def test_ssh_enable(self):
        with patch.object(v,'routeros_session',self.session):r=v.management_enable(1,v.EnableService(service='ssh',source='10.110.0.109/32'),self.db,self.user)
        self.assertEqual(r['address'],'10.110.0.109/32');self.assertEqual(self.d.port,8728)
if __name__=='__main__':unittest.main()
