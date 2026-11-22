import json
import unittest
from datetime import datetime,timezone,timedelta
from unittest.mock import patch
from test_management_jobs import Queue as ExistingQueue,m
from app.services import account_jobs as a
from fastapi import HTTPException

PW='unit-test-secret-not-real'
class Path:
    def __init__(self,api,kind):self.api=api;self.kind=kind
    def __iter__(self):return iter([dict(r) for r in self.api.rows[self.kind]])
    def add(self,**kw):
        self.api.writes.append('add');self.api.rows[self.kind].append({'.id':'*new',**{k:v for k,v in kw.items() if k!='password'}})
    def update(self,**kw):
        self.api.writes.append('update');next(r for r in self.api.rows[self.kind] if r['.id']==kw['.id']).update({k:v for k,v in kw.items() if k!='password'})
    def remove(self,i):self.api.writes.append('delete');self.api.rows[self.kind]=[r for r in self.api.rows[self.kind] if r['.id']!=i]
class API:
    def __init__(self):self.writes=[];self.rows={('user',):[{'.id':'*1','name':'roszetta','group':'full','address':'10.0.0.1/32'},{'.id':'*2','name':'staff','group':'read','address':'192.0.2.1/32'}],('user','group'):[{'name':'read'},{'name':'full'}]}
    def path(self,*p):return Path(self,p)

class UserOperations(unittest.TestCase):
    def setUp(self):self.api=API();self.spec=dict(username='staff',group='read',address='',update_existing=False)
    def test_create(self):
        r=a.user_operation(self.api,'user-add','roszetta',dict(self.spec,username='new'),PW);self.assertEqual(r['account_status'],'created');self.assertNotIn(PW,str(r))
    def test_existing_skip(self):
        self.assertEqual(a.user_operation(self.api,'user-add','roszetta',self.spec,PW)['account_status'],'skipped');self.assertFalse(self.api.writes)
    def test_missing_group(self):
        with self.assertRaisesRegex(a.AccountBlocked,'Группа не найдена'):a.user_operation(self.api,'user-add','roszetta',dict(self.spec,username='new',group='missing'),PW)
        self.assertFalse(self.api.writes)
    def test_update_preserves_address(self):
        a.user_operation(self.api,'user-add','roszetta',dict(self.spec,update_existing=True),PW);self.assertEqual(self.api.rows[('user',)][1]['address'],'192.0.2.1/32')
    def test_change_password(self):
        self.assertEqual(a.user_operation(self.api,'user-password','roszetta',{'username':'staff'},PW)['account_status'],'updated')
    def test_delete(self):
        self.assertEqual(a.user_operation(self.api,'user-delete','roszetta',{'username':'staff'},'')['account_status'],'deleted')
    def test_delete_missing(self):
        self.assertEqual(a.user_operation(self.api,'user-delete','roszetta',{'username':'missing'},'')['account_status'],'skipped');self.assertFalse(self.api.writes)
    def test_controller_protected(self):
        for action in ('user-add','user-password','user-delete'):
            with self.assertRaises(a.AccountBlocked):a.user_operation(self.api,action,'roszetta',dict(self.spec,username='roszetta',update_existing=True),PW)
        self.assertFalse(self.api.writes)
    def test_controller_same_password_noop(self):
        r=a.user_operation(self.api,'user-add','roszetta',dict(self.spec,username='roszetta',group='full',update_existing=True),PW,True);self.assertEqual(r['account_status'],'skipped');self.assertFalse(self.api.writes)
    def test_last_full_protected(self):
        for action in ('user-delete','user-add'):
            with self.assertRaisesRegex(a.AccountBlocked,'последнего'):a.user_operation(self.api,action,'other',dict(self.spec,username='roszetta',update_existing=True),PW)
        self.assertFalse(self.api.writes)
    def test_ambiguous_write_sanitized(self):
        with patch.object(Path,'update',side_effect=RuntimeError(PW)),self.assertRaises(a.AccountUnconfirmed) as ex:
            a.user_operation(self.api,'user-password','roszetta',{'username':'staff'},PW)
        self.assertNotIn(PW,str(ex.exception))
    def test_group_list(self):
        self.assertEqual(a.user_operation(self.api,'user-groups','roszetta',{},'')['account_groups'],['full','read']);self.assertFalse(self.api.writes)
    def test_validation(self):
        r=a.normalize_request(dict(action='user-add',ids=[1,1,2],username='staff',group='read',password=PW,address='192.0.2.1',confirmed=True));self.assertEqual(r[1],[1,2]);self.assertEqual(r[2]['address'],'192.0.2.1/32')
        for change in ({'action':[]},{'ids':[True]},{'password':'x'},{'username':'x y'},{'address':'invalid'},{'confirmed':False}):
            with self.assertRaises(a.AccountBlocked):a.normalize_request(dict(dict(action='user-add',ids=[1],username='staff',group='read',password=PW,confirmed=True),**change))

class AccountQueue(unittest.TestCase):
    def setUp(self):
        self.f=ExistingQueue();self.f.setUp();self.addCleanup(self.f.tearDown);self.db=self.f.db
        self.cipher='v2:test-ciphertext'; self.vault=m.vault_service
        self.vault.encrypt_secret=lambda password:self.cipher
        self.vault.decrypt_secret_v2=lambda token:PW
    def new(self,action='user-add',ids=None,**kw):
        body=dict(action=action,ids=ids or [1,2],username='staff',group='read',password=PW,confirmed=True,allow_plain=True,request_id='00000000000000001');body.update(kw)
        # Production advisory lock is PostgreSQL-specific; exercise the rest on SQLite.
        original=self.db.execute
        def execute(statement,*args,**kwargs):
            if 'pg_advisory_xact_lock' in str(statement):return None
            return original(statement,*args,**kwargs)
        with patch.object(self.db,'execute',side_effect=execute):return m.create_account_job(body,self.db,self.f.user)
    def secret(self,id):self.db.expire_all();return self.db.get(m.AccountJobSecret,id)
    def test_enqueue_no_remote_and_secret_is_separate(self):
        with patch.object(m,'execute_account_job') as f:j=self.new();f.assert_not_called()
        self.assertNotIn(PW,json.dumps(j,default=str));self.assertNotIn(self.cipher,str(j));self.assertEqual(self.secret(j['id']).token,self.cipher)
    def test_plain_requires_confirmation(self):
        with self.assertRaises(HTTPException):self.new(allow_plain=False)
    def test_deduplicate_request(self):
        one=self.new();two=self.new();self.assertEqual(one['id'],two['id'])
    def test_duplicate_active_block(self):
        self.new();self.assertRaises(HTTPException,self.new,request_id='00000000000000002')
    def test_continue_after_precondition_failure_and_cleanup(self):
        j=self.new()
        with patch.object(m,'execute_account_job',side_effect=[m.Blocked('precheck'),{'detail':'done'}]):m.tick();m.tick()
        self.assertEqual(self.f.job(j).state,'failed');self.assertEqual([e['state'] for e in self.f.job(j).entries],['failed','done']);self.assertIsNone(self.secret(j['id']))
    def test_ambiguous_stops_and_cleanup(self):
        j=self.new()
        with patch.object(m,'execute_account_job',side_effect=m.Unconfirmed('unknown')) as f:m.tick();m.tick();self.assertEqual(f.call_count,1)
        self.assertEqual(self.f.job(j).state,'interrupted');self.assertIsNone(self.secret(j['id']))
    def test_stop_removes_secret(self):
        j=self.new();m.stop(j['id'],self.db,self.f.user);self.assertIsNone(self.secret(j['id']))
    def test_success_removes_secret(self):
        j=self.new(ids=[1]);
        with patch.object(m,'execute_account_job',return_value={'detail':'done'}):m.tick()
        self.assertEqual(self.f.job(j).state,'done');self.assertIsNone(self.secret(j['id']))
    def test_expiry(self):
        j=self.new();s=self.secret(j['id']);s.expires=datetime.now(timezone.utc)-timedelta(seconds=5);self.db.commit()
        with patch.object(m,'execute_account_job') as f:m.tick();f.assert_not_called()
        self.assertEqual(self.f.job(j).state,'failed');self.assertIsNone(self.secret(j['id']))
    def test_retry_only_unexecuted(self):
        j=self.new()
        with patch.object(m,'execute_account_job',side_effect=[m.Blocked('precheck'),{'detail':'done'}]):m.tick();m.tick()
        self.db.expire_all()
        with self.assertRaises(HTTPException):self.new(ids=[2],retry_job=j['id'],request_id='00000000000000002')
        self.assertEqual(len(self.new(ids=[1],retry_job=j['id'],request_id='00000000000000003')['entries']),1)
    def test_read_no_password(self):
        j=self.new(action='user-groups');self.assertIsNone(self.secret(j['id']))
    def test_recovery_does_not_replay(self):
        j=self.new();old=self.f.job(j);old.state='running';old.entries=[dict(old.entries[0],state='running'),old.entries[1]];self.db.commit()
        with patch.object(m,'execute_account_job') as f:m.tick();f.assert_not_called()
        self.assertEqual(self.f.job(j).state,'interrupted');self.assertIsNone(self.secret(j['id']))
