"""v0.8.7: connection queue, authentication marker and NTP formatting (no live network)."""
import sys,types
import json
import unittest
from contextlib import contextmanager
from unittest.mock import patch
from fastapi import HTTPException
import test_management_jobs as existing
m, Device, FakeAPI = existing.m, existing.Device, existing.FakeAPI
from app.services import time_management as tm
security=types.ModuleType("app.core.security");security.decode_token=lambda token:{};security.encrypt_secret=lambda pwd:"v2:new"
with patch.dict(sys.modules,{"app.core.security":security}):
    from app.api import deps
client=types.ModuleType("app.services.routeros.client")
class Credentials:
    def __init__(self,**kwargs): self.__dict__.update(kwargs)
client.RouterOSCredentials=Credentials
client.routeros_session=lambda creds:None

PW='fake-password-for-unit-test'

class Connections(unittest.TestCase):
    def setUp(self):
        self.f=existing.Queue();self.f.setUp();self.addCleanup(self.f.tearDown);self.db=self.f.db
        modules=patch.dict(sys.modules,{"app.core.security":security,"app.services.routeros.client":client});modules.start();self.addCleanup(modules.stop)
        m.vault_service.encrypt_secret=lambda password:'v2:fake-cipher'
        m.vault_service.decrypt_secret_v2=lambda token:PW
    def new(self,**kwargs):
        body=dict(ids=[1,2],username='new-user',password=PW,transport='keep',apply=True,confirmed=True,allow_plain=True,request_id='00000000000000001');body.update(kwargs)
        original=self.db.execute
        def execute(statement,*args,**kw):
            if 'pg_advisory_xact_lock' in str(statement):return None
            return original(statement,*args,**kw)
        with patch.object(self.db,'execute',side_effect=execute):return m.create_connection_job(body,self.db,self.f.user)
    def test_enqueue_and_dedupe(self):
        j=self.new();self.assertEqual(j['id'],self.new()['id']);r=json.dumps(j,default=str)
        self.assertNotIn(PW,r);self.assertNotIn('fake-cipher',r);self.assertNotIn('credential_revision',r)
        self.assertEqual(self.db.get(m.AccountJobSecret,j['id']).token,'v2:fake-cipher')
    def test_invalid_password_does_not_echo(self):
        with self.assertRaises(HTTPException) as e:self.new(password=PW*20)
        self.assertNotIn(PW,str(e.exception.detail))
    def test_plain_not_confirmed(self):
        with self.assertRaises(HTTPException):self.new(allow_plain=False)
    def test_apply_not_confirmed(self):
        with self.assertRaises(HTTPException):self.new(confirmed=False)
    def test_overlap_blocked(self):
        self.new()
        with self.assertRaises(HTTPException):self.new(request_id='00000000000000002')
    def test_no_pin_no_new_password_sent(self):
        j=self.new(ids=[1],transport='api-ssl')
        with patch.object(client,'routeros_session') as session:m.tick();session.assert_not_called()
        self.assertEqual(self.f.job(j).state,'failed');self.assertIsNone(self.db.get(m.AccountJobSecret,j['id']))
    def test_pin_mismatch_no_login(self):
        d=self.db.get(Device,1);d.port=8729;d.use_tls=True;d.tls_fingerprint='a'*64;self.db.commit()
        j=self.new(ids=[1],allow_plain=False)
        with patch.object(m,'peer_certificate',return_value=('b'*64,'valid')),patch.object(client,'routeros_session') as session:m.tick();session.assert_not_called()
        self.assertEqual(self.f.job(j).state,'failed');self.assertEqual(self.db.get(Device,1).username,'roszetta')
    def test_downgrade_blocked(self):
        d=self.db.get(Device,1);d.port=8729;d.use_tls=True;d.tls_fingerprint='a'*64;self.db.commit()
        j=self.new(ids=[1],transport='api')
        with patch.object(client,'routeros_session') as session:m.tick();session.assert_not_called()
        self.assertEqual(self.f.job(j).state,'failed')
    def test_stale_credentials_blocked(self):
        j=self.new(ids=[1]);self.db.get(Device,1).password_enc='different-cipher';self.db.commit()
        with patch.object(client,'routeros_session') as session:m.tick();session.assert_not_called()
        self.assertEqual(self.f.job(j).state,'failed')
    def test_custom_port_kept(self):
        d=self.db.get(Device,1);d.port=18728
        self.assertEqual(m.connection_target(d,'api'),(18728,False))
    def fake_session(self):
        a=FakeAPI();a.rows[('system','identity')]=[{'name':'remote'}];a.rows[('system','resource')]=[{'version':'7'}]
        @contextmanager
        def session(creds):yield a
        return session
    def test_check_never_saves(self):
        j=self.new(ids=[1],apply=False)
        with patch.object(client,'routeros_session',self.fake_session()):m.tick()
        self.assertEqual(self.f.job(j).state,'done');self.assertEqual(self.db.get(Device,1).username,'roszetta');self.assertIsNone(self.db.get(m.AccountJobSecret,j['id']))
    def test_save_success(self):
        j=self.new(ids=[1])
        with patch.object(client,'routeros_session',self.fake_session()):m.tick()
        self.assertEqual(self.f.job(j).state,'done');self.assertEqual(self.db.get(Device,1).username,'new-user');self.assertEqual(self.db.get(Device,1).password_enc,'v2:new');self.assertIsNone(self.db.get(m.AccountJobSecret,j['id']))
    def test_login_failure_sanitized_and_continues(self):
        j=self.new()
        with patch.object(client,'routeros_session',side_effect=RuntimeError(PW)):m.tick();m.tick()
        row=self.f.job(j);self.assertEqual(row.state,'failed');self.assertEqual([e['state'] for e in row.entries],['failed','failed']);self.assertNotIn(PW,str(row.entries));self.assertIsNone(self.db.get(m.AccountJobSecret,j['id']))
    def test_stop_removes_secret(self):
        j=self.new();m.stop(j['id'],self.db,self.f.user);self.assertIsNone(self.db.get(m.AccountJobSecret,j['id']))

class SessionTests(unittest.TestCase):
    def test_auth_failure_has_marker(self):
        with patch.object(deps,'decode_token',side_effect=ValueError('bad')),self.assertRaises(HTTPException) as e:deps.get_current_user('invalid',None)
        self.assertEqual(e.exception.status_code,401);self.assertEqual(e.exception.headers['X-ROSzetta-Auth'],'session')
    def test_readable_positive_and_negative(self):
        self.assertEqual(tm.format_offset(90061),'+1 дн. 1 ч 1 мин 1 с');self.assertEqual(tm.format_offset(-3600),'−1 ч');self.assertEqual(tm.format_offset(0),'0 с')
