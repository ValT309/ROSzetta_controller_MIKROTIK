"""Stage 2 unit and SQLite worker tests. No live RouterOS or PostgreSQL writes."""
import os, sys, types, unittest
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi import HTTPException
os.environ['DATABASE_URL']='sqlite://'
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
# Stub unavailable crypto auth dependencies only; real SQLAlchemy and application models.
security=types.ModuleType('app.core.security');security.decode_token=lambda x:{}
with patch.dict(sys.modules,{'app.core.security':security}):
    from app.services import management_jobs as m
from app.core.db import Base
from app.models.device import Device
from app.models.user import User
from app.models.device_management import DeviceManagementEvent

SOURCE='10.110.0.109/32'
class ApiPath:
    def __init__(self,api,path): self.api=api;self.path=path
    def __iter__(self):return iter([dict(r) for r in self.api.rows.get(self.path,[])])
    def __call__(self,cmd,**args):
        self.api.calls.append((self.path,cmd,dict(args)))
        for r in self.api.rows[self.path]:
            if args.get('.id')==r.get('.id'):r.update(args)
        return []
class FakeAPI:
    def __init__(self):
        self.calls=[]; self.rows={
          ('user',):[{'.id':'*10','name':'roszetta','group':'roszetta','address':SOURCE,'disabled':False}],
          ('user','group'):[{'.id':'*20','name':'roszetta','policy':'!ssh,ftp,read,write,api,policy,reboot,!web'}],
          ('user','aaa'):[{'use-radius':False}],
          ('certificate',):[],('ip','service'):[{'.id':'*1','name':'api','port':8728,'disabled':False,'address':SOURCE},{'.id':'*2','name':'api-ssl','disabled':True,'port':8729,'address':'','certificate':'none'}]}
    def path(self,*p):return ApiPath(self,p)
    def __call__(self,cmd,**args):
        self.calls.append((cmd,dict(args)))
        if cmd=='/certificate/add':self.rows[('certificate',)].append({'.id':'*'+str(30+len(self.rows[('certificate',)])),**args})
        elif cmd=='/certificate/sign':
            row=next(r for r in self.rows[('certificate',)] if r['name']==args['number'])
            assert args['name']==row['name']
            if 'key-cert-sign' in row.get('key-usage',''):
                row.update(fingerprint='c'*64,authority=True,**{'private-key':True,'trusted':True})
            else:
                assert args.get('ca')=='roszetta-ca'
                assert any(r.get('name')==args['ca'] and r.get('authority') for r in self.rows[('certificate',)])
                row.update(fingerprint='a'*64,ca=args['ca'],**{'private-key':True,'trusted':False})
        else:raise RuntimeError('unexpected command')
        return []

class Permissions(unittest.TestCase):
    def setUp(self):self.api=FakeAPI();self.snap=m.account_snapshot(self.api,'roszetta')
    def test_add_missing_only(self):
        r=m.apply_rights(self.api,'roszetta',self.snap,SOURCE)
        self.assertEqual(r['missing'],[]);self.assertEqual(set(r['policies']),{'ssh','ftp','read','write','api','policy','reboot'});self.assertEqual(len(self.api.calls),1)
    def test_both_missing(self):
        self.api.rows[('user','group')][0]['policy']='!ssh,!ftp,read,write,api,policy'; s=m.account_snapshot(self.api,'roszetta');self.assertEqual(m.apply_rights(self.api,'roszetta',s,SOURCE)['missing'],[])
    def test_changed_permissions(self):
        self.api.rows[('user','group')][0]['policy']+=',sniff'
        with self.assertRaises(m.Blocked):m.apply_rights(self.api,'roszetta',self.snap,SOURCE)
        self.assertFalse(self.api.calls)
    def test_shared_group(self):
        self.api.rows[('user',)].append({'name':'other','group':'roszetta'});s=m.account_snapshot(self.api,'roszetta')
        with self.assertRaises(m.Blocked):m.apply_rights(self.api,'roszetta',s,SOURCE)
        self.assertFalse(self.api.calls)
    def test_radius(self):
        self.api.rows[('user','aaa')][0]['use-radius']=True;s=m.account_snapshot(self.api,'roszetta')
        with self.assertRaises(m.Blocked):m.desired_policies(s,SOURCE)
    def test_unrestricted(self):
        self.api.rows[('user',)][0]['address']='';s=m.account_snapshot(self.api,'roszetta')
        with self.assertRaises(m.Blocked):m.desired_policies(s,SOURCE)
    def test_source_mismatch(self):
        with self.assertRaises(m.Blocked):m.desired_policies(self.snap,'192.0.2.1/32')
    def test_disabled(self):
        self.api.rows[('user',)][0]['disabled']=True;s=m.account_snapshot(self.api,'roszetta')
        with self.assertRaises(m.Blocked):m.desired_policies(s,SOURCE)
    def test_builtin(self):
        s=dict(self.snap,group='full')
        with self.assertRaises(m.Blocked):m.desired_policies(s,SOURCE)
    def test_no_other_base_rights_added(self):
        s=dict(self.snap,base_missing=['write'])
        with self.assertRaises(m.Blocked):m.desired_policies(s,SOURCE)
    def test_invalid_group(self):
        self.api.rows[('user','group')]=[]
        with self.assertRaises(m.Blocked):m.account_snapshot(self.api,'roszetta')
    def test_no_radius_data(self):
        self.api.rows[('user','aaa')]=[];s=m.account_snapshot(self.api,'roszetta')
        with self.assertRaises(m.Blocked):m.desired_policies(s,SOURCE)

class Certificates(unittest.TestCase):
    def setUp(self):self.api=FakeAPI();self.d=types.SimpleNamespace(host='192.0.2.1',use_tls=False,port=8728,tls_fingerprint=None)
    def test_new_certificate(self):
        cert,port,fp,old,row=m.prepare_tls(self.api,self.d,SOURCE)
        self.assertTrue(cert.startswith('roszetta-api-'));self.assertEqual((port,fp),(8729,'a'*64));self.assertTrue(old['disabled']);self.assertFalse(m.mg.truth(row['disabled']));self.assertEqual(row['address'],SOURCE);self.assertEqual(self.api.rows[('ip','service')][0]['port'],8728);self.assertFalse(self.api.rows[('ip','service')][0]['disabled'])
    def test_existing_certificate(self):
        self.api.rows[('ip','service')][1]['certificate']='current';self.api.rows[('certificate',)]=[{'.id':'*3','name':'current','fingerprint':'b'*64,'private-key':True,'key-usage':'tls-server'}]
        result=m.prepare_tls(self.api,self.d,SOURCE);self.assertEqual(result[:3],('current',8729,'b'*64));self.assertEqual(len(self.api.calls),1)
    def test_already_tls(self):
        self.d.use_tls=True
        with self.assertRaises(m.Blocked):m.prepare_tls(self.api,self.d,SOURCE)
        self.assertFalse(self.api.calls)
    def test_already_enabled(self):
        self.api.rows[('ip','service')][1]['disabled']=False
        with self.assertRaises(m.Blocked):m.prepare_tls(self.api,self.d,SOURCE)
        self.assertFalse(self.api.calls)
    def test_unrestricted_network(self):
        self.api.rows[('ip','service')][1]['address']='0.0.0.0/0'
        with self.assertRaises(m.Blocked):m.prepare_tls(self.api,self.d,SOURCE)
        self.assertFalse(self.api.calls)
    def test_preserve_addresses(self):
        self.api.rows[('ip','service')][1]['address']='192.0.2.0/24';r=m.prepare_tls(self.api,self.d,SOURCE);self.assertEqual(set(r[-1]['address'].split(',')),{'192.0.2.0/24',SOURCE})
    def test_sign_error_does_not_enable(self):
        class Failing(FakeAPI):
            def __call__(self,cmd,**kw):
                if cmd=='/certificate/sign':raise RuntimeError('raw confidential error')
                return super().__call__(cmd,**kw)
        self.api=Failing()
        with self.assertRaises(m.Unconfirmed) as e:m.prepare_tls(self.api,self.d,SOURCE)
        self.assertNotIn('raw confidential',str(e.exception));self.assertTrue(self.api.rows[('ip','service')][1]['disabled'])

    def test_signs_root_first_then_leaf(self):
        m.prepare_tls(self.api,self.d,SOURCE)
        commands=[c for c in self.api.calls if c[0]=='/certificate/sign']
        self.assertEqual(len(commands),2)
        self.assertEqual(commands[0][1]['number'],'roszetta-ca')
        self.assertEqual(commands[1][1]['ca'],'roszetta-ca')
        self.assertFalse(m.mg.truth(self.api.rows[('certificate',)][0].get('trusted')))
    def test_reuses_unsigned_old_template(self):
        self.api.rows[('certificate',)]=[{'.id':'*40','name':'roszetta-api-20247b22a288','common-name':self.d.host,'subject-alt-name':'IP:'+self.d.host,'key-usage':'tls-server,digital-signature'}]
        result=m.prepare_tls(self.api,self.d,SOURCE)
        self.assertEqual(result[0],'roszetta-api-20247b22a288')
        self.assertEqual(len(self.api.rows[('certificate',)]),2)
    def test_reuses_signed_template_no_ca_write(self):
        self.api.rows[('certificate',)]=[{'.id':'*40','name':'roszetta-api-20247b22a288','common-name':self.d.host,'subject-alt-name':'IP:'+self.d.host,'key-usage':'tls-server','private-key':True,'fingerprint':'b'*64}]
        self.assertEqual(m.prepare_tls(self.api,self.d,SOURCE)[0],'roszetta-api-20247b22a288')
        self.assertEqual(len(self.api.calls),1)
    def test_enabled_certificate_preserved(self):
        self.api.rows[('ip','service')][1].update(disabled=False,certificate='existing',address=SOURCE)
        self.api.rows[('certificate',)]=[{'.id':'*40','name':'existing','key-usage':'tls-server','private-key':True,'fingerprint':'b'*64}]
        self.assertEqual(m.prepare_tls(self.api,self.d,SOURCE)[0],'existing');self.assertFalse(self.api.calls)
    def test_existing_ca_reused(self):
        self.api.rows[('certificate',)]=[{'.id':'*50','name':'roszetta-ca','common-name':'ROSzetta-CA','key-usage':'key-cert-sign,crl-sign','private-key':True,'authority':True,'fingerprint':'c'*64,'trusted':True}]
        m.prepare_tls(self.api,self.d,SOURCE)
        self.assertTrue(self.api.rows[('certificate',)][0]['trusted'])
        self.assertEqual(len([c for c in self.api.calls if c[0]=='/certificate/sign']),1)
    def test_ca_name_collision(self):
        self.api.rows[('certificate',)]=[{'.id':'*50','name':'roszetta-ca','common-name':'other','key-usage':'tls-server'}]
        with self.assertRaises(m.Blocked):m.prepare_tls(self.api,self.d,SOURCE)
        self.assertFalse(self.api.calls)
    def test_async_sign_wait(self):
        class Delayed(FakeAPI):
            def __init__(self):super().__init__();self.todo=None;self.counter=0
            def __call__(self,cmd,**args):
                if cmd=='/certificate/sign':self.todo=(cmd,args);self.counter=0;return []
                return super().__call__(cmd,**args)
            def path(self,*p):
                if p==('certificate',) and self.todo:
                    self.counter+=1
                    if self.counter>=3:
                        cmd,args=self.todo;self.todo=None;super().__call__(cmd,**args)
                return super().path(*p)
        with patch.object(m.time,'sleep') as sleep:
            m.prepare_tls(Delayed(),self.d,SOURCE)
            self.assertGreaterEqual(sleep.call_count,4)
    def test_old_version_does_not_send_trust_store(self):
        self.api.rows[('system','resource')]=[{'version':'7.12.1 (stable)'}]
        m.prepare_tls(self.api,self.d,SOURCE)
        self.assertFalse(any('trust-store' in c[1] for c in self.api.calls if c[0]=='/certificate/add'))
    def test_recent_version_scopes_ca(self):
        self.api.rows[('system','resource')]=[{'version':'7.23.6 (long-term)'}]
        m.prepare_tls(self.api,self.d,SOURCE)
        self.assertEqual(self.api.rows[('certificate',)][0]['trust-store'],'api')

class SSLInventory(unittest.TestCase):
    def setUp(self):
        self.api=FakeAPI();self.d=types.SimpleNamespace(host='192.0.2.1',use_tls=False,port=8728,tls_fingerprint=None)
    def leaf(self,**kw):
        row={'.id':'*40','name':'roszetta-api-20247b22a288','common-name':self.d.host,'key-usage':'tls-server','private-key':True,'fingerprint':'b'*64,'expires-after':'52w23h59m51s'};row.update(kw);self.api.rows[('certificate',)]=[row];return row
    def test_none(self):self.assertEqual(m.inspect_ssl(self.d,self.api)['status'],'none')
    def test_unrelated_cert(self):
        self.leaf(name='vpn');self.assertEqual(m.inspect_ssl(self.d,self.api)['status'],'none')
    def test_issued(self):
        self.leaf();r=m.inspect_ssl(self.d,self.api);self.assertEqual(r['status'],'issued');self.assertIsNotNone(datetime.fromisoformat(r['expires']).tzinfo)
    def test_unsigned(self):
        self.leaf(fingerprint='',**{'private-key':False});self.assertEqual(m.inspect_ssl(self.d,self.api)['status'],'attention')
    def test_assigned_enabled_not_switched(self):
        row=self.leaf();self.api.rows[('ip','service')][1].update(disabled=False,certificate=row['name'])
        with patch.object(m,'peer_certificate',return_value=('b'*64,'2028-01-01T00:00:00+00:00')):self.assertEqual(m.inspect_ssl(self.d,self.api)['status'],'attention')
    def test_secure_requires_pin_and_actual_tls(self):
        row=self.leaf();self.api.rows[('ip','service')][1].update(disabled=False,certificate=row['name']);self.d.use_tls=True;self.d.port=8729;self.d.tls_fingerprint='b'*64
        with patch.object(m,'peer_certificate',return_value=('b'*64,'2028-01-01T00:00:00+00:00')):self.assertEqual(m.inspect_ssl(self.d,self.api)['status'],'secure')
        with patch.object(m,'peer_certificate',return_value=('d'*64,'2028-01-01T00:00:00+00:00')):self.assertEqual(m.inspect_ssl(self.d,self.api)['status'],'error')
    def test_expired_assigned(self):
        row=self.leaf(expired=True);self.api.rows[('ip','service')][1].update(certificate=row['name']);self.assertEqual(m.inspect_ssl(self.d,self.api)['status'],'error')
    def test_dropdown_only_signed_leaf(self):
        row=self.leaf();self.api.rows[('certificate',)].append({'name':'root','private-key':True,'fingerprint':'c'*64,'key-usage':'key-cert-sign'});self.assertEqual([r['name'] for r in m.cert_summary(self.api)],[row['name']])

class PeerCertificate(unittest.TestCase):
    def der(self,expired=False):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes,serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
        from datetime import timedelta
        now=datetime.now(timezone.utc);key=ec.generate_private_key(ec.SECP256R1());name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'test')])
        c=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(now-timedelta(days=2)).not_valid_after(now+timedelta(days=-1 if expired else 1)).sign(key,hashes.SHA256())
        return c.public_bytes(serialization.Encoding.DER)
    def check(self,der):
        from unittest.mock import MagicMock
        ctx=MagicMock();ctx.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value=der
        with patch.object(m.socket,'create_connection',return_value=MagicMock()),patch.object(m.ssl,'SSLContext',return_value=ctx):return m.peer_certificate('192.0.2.1',8729)
    def test_fingerprint(self):
        import hashlib
        der=self.der();self.assertEqual(self.check(der)[0],hashlib.sha256(der).hexdigest())
    def test_expired(self):
        with self.assertRaises(m.Blocked):self.check(self.der(expired=True))
    def test_missing(self):
        with self.assertRaises(m.Blocked):self.check(None)

class Queue(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite://');self.Session=sessionmaker(bind=self.engine);Base.metadata.create_all(self.engine,tables=[Device.__table__,User.__table__,DeviceManagementEvent.__table__,m.ManagementJob.__table__,m.SSLStatus.__table__,m.AccountJobSecret.__table__]);self.db=self.Session()
        self.db.add(User(id=1,email='test',hashed_password='dummy',role='admin',is_active=True))
        for i in (1,2):self.db.add(Device(id=i,name=str(i),host=f'192.0.2.{i}',username='roszetta',password_enc='NOT STORED',port=8728,use_tls=False))
        self.db.commit();self.user=self.db.get(User,1)
        self.ctx=patch.multiple(m,engine=types.SimpleNamespace(dialect=types.SimpleNamespace(name='postgresql')),SessionLocal=self.Session,scan_due=lambda db:None,vault_service=types.SimpleNamespace(is_initialized_cached=lambda:False,is_unlocked=lambda:True));self.ctx.start()
    def tearDown(self):self.ctx.stop();self.db.close();self.engine.dispose()
    def create(self,action='rights',ids=[1,2],**kw):return m.create(m.Request(action=action,ids=ids,**kw),self.db,self.user)
    def job(self,j):self.db.expire_all();return self.db.get(m.ManagementJob,j['id'])
    def test_no_confirmation(self):
        with self.assertRaises(HTTPException):self.create('ssh')
    def test_no_preview(self):
        with self.assertRaises(HTTPException):self.create('rights-apply',confirmed=True)
    def test_bad_source(self):
        with self.assertRaises(HTTPException):self.create(source='0.0.0.0/0')
    def test_no_credentials_stored(self):
        j=self.create();self.assertNotIn('NOT STORED',str(j))
    def test_worker_runs_once_per_tick(self):
        j=self.create()
        with patch.object(m,'execute',return_value={'detail':'OK'}) as f:
            m.tick();self.assertEqual(self.job(j).state,'queued');m.tick();self.assertEqual(self.job(j).state,'done');m.tick();self.assertEqual(f.call_count,2)
    def test_stop(self):
        j=self.create()
        with patch.object(m,'execute',return_value={'detail':'OK'}) as f:
            m.tick();self.db.expire_all();m.stop(j['id'],self.db,self.user);m.tick();self.assertEqual(f.call_count,1);self.assertEqual(self.job(j).state,'stopped')
    def test_locked_vault(self):
        j=self.create()
        with patch.object(m,'vault_service',types.SimpleNamespace(is_initialized_cached=lambda:True,is_unlocked=lambda:False)),patch.object(m,'execute') as f:
            m.tick();f.assert_not_called();self.assertEqual(self.job(j).state,'queued')
    def test_read_error_continues(self):
        j=self.create()
        with patch.object(m,'execute',side_effect=[Exception('secret'),{'detail':'OK'}]):m.tick();m.tick()
        self.assertEqual(self.job(j).state,'failed');self.assertEqual([e['state'] for e in self.job(j).entries],['failed','done']);self.assertNotIn('secret',str(self.job(j).entries))
    def test_ambiguous_write_stops(self):
        j=self.create('ssh',confirmed=True)
        with patch.object(m,'execute',side_effect=Exception('secret')) as f:m.tick();m.tick();self.assertEqual(f.call_count,1)
        self.assertEqual(self.job(j).state,'interrupted');self.assertEqual([e['state'] for e in self.job(j).entries],['unknown','pending']);self.assertEqual(self.db.query(DeviceManagementEvent).count(),1)
    def test_precondition_failure_continues(self):
        j=self.create('ssh',confirmed=True)
        with patch.object(m,'execute',side_effect=[m.Blocked('precheck'),{'detail':'OK'}]):m.tick();m.tick()
        self.assertEqual(self.job(j).state,'failed');self.assertEqual([e['state'] for e in self.job(j).entries],['failed','done'])
    def test_recovery_no_replay(self):
        j=self.create('ssh',confirmed=True);row=self.job(j);row.state='running';row.entries=[dict(row.entries[0],state='running'),row.entries[1]];self.db.commit()
        with patch.object(m,'execute') as f:m.tick();f.assert_not_called()
        self.assertEqual(self.job(j).state,'interrupted');self.assertEqual(self.job(j).entries[0]['state'],'unknown')
    def test_changed_host_stops_write_for_that_device(self):
        j=self.create('ssh',confirmed=True,ids=[1]);self.db.get(Device,1).host='192.0.2.99';self.db.commit()
        with patch.object(m,'execute') as f:m.tick();f.assert_not_called()
        self.assertEqual(self.job(j).state,'failed')
    def test_preview_binding(self):
        p=self.create('rights',ids=[1]);
        with patch.object(m,'execute',return_value={'detail':'OK','eligible':True,'snapshot':{'test':True}}):m.tick()
        j=self.create('rights-apply',confirmed=True,ids=[1],preview_job=p['id']);self.assertEqual(j['entries'][0]['expected']['snapshot'],{'test':True})
        with self.assertRaises(HTTPException):self.create('rights-apply',confirmed=True,ids=[2],preview_job=p['id'])
        with self.assertRaises(HTTPException):self.create('tls-switch',confirmed=True,ids=[1],preview_job=p['id'])
    def test_revoked_admin(self):
        j=self.create('ssh',confirmed=True);self.user.role='operator';self.db.commit()
        with patch.object(m,'execute') as f:m.tick();f.assert_not_called()
        self.assertEqual(self.job(j).state,'failed')

    def test_single_tls_preparation_status_tracks_queue(self):
        self.assertIsNone(m.tls_preparation_status(1,self.db,self.user))
        job=self.create('tls-prepare',ids=[1],confirmed=True)
        result=m.tls_preparation_status(1,self.db,self.user)
        self.assertEqual((result['id'],result['state'],result['active']),(job['id'],'pending',True))
        self.assertIsNone(m.tls_preparation_status(2,self.db,self.user))
        with patch.object(m,'execute',return_value={'detail':'prepared'}):m.tick()
        self.db.expire_all();result=m.tls_preparation_status(1,self.db,self.user)
        self.assertEqual((result['state'],result['active'],result['detail']),('done',False,'prepared'))
    def test_tls_preparation_duplicate_rejected(self):
        self.create('tls-prepare',ids=[1,2],confirmed=True)
        with self.assertRaises(HTTPException) as exc:self.create('tls-prepare',ids=[1],confirmed=True)
        self.assertEqual(exc.exception.status_code,409)
    def test_tls_preparation_status_stopped_pending(self):
        job=self.create('tls-prepare',ids=[1],confirmed=True)
        m.stop(job['id'],self.db,self.user)
        result=m.tls_preparation_status(1,self.db,self.user)
        self.assertEqual((result['state'],result['job_state'],result['active']),('pending','stopped',False))
    def test_tls_preparation_status_interrupted(self):
        job=self.create('tls-prepare',ids=[1],confirmed=True)
        with patch.object(m,'execute',side_effect=m.Unconfirmed('check')):m.tick()
        self.db.expire_all();result=m.tls_preparation_status(1,self.db,self.user)
        self.assertEqual((result['state'],result['job_state'],result['active']),('unknown','interrupted',False))
    def test_resume_tls_preserves_history(self):
        j=self.create('tls-prepare',confirmed=True)
        with patch.object(m,'execute',side_effect=m.Unconfirmed('check')):m.tick()
        new=m.resume_tls(j['id'],self.db,self.user)
        self.assertEqual([e['id'] for e in new['entries']],[1,2]);self.assertEqual(self.job(j).state,'interrupted')
        with self.assertRaises(HTTPException):m.resume_tls(j['id'],self.db,self.user)
    def test_resume_excludes_done(self):
        j=self.create('tls-prepare',confirmed=True,ids=[1,2]);row=self.job(j);row.entries=[dict(row.entries[0],state='done'),row.entries[1]];row.state='stopped';self.db.commit()
        new=m.resume_tls(j['id'],self.db,self.user);self.assertEqual([e['id'] for e in new['entries']],[2])
    def test_status_cache_endpoint_change_unknown(self):
        d=self.db.get(Device,1);self.db.add(m.SSLStatus(device_id=1,checked_at=datetime.now(timezone.utc),data={'status':'secure','endpoint':[d.host,d.port,d.use_tls,d.tls_fingerprint]}));self.db.commit()
        self.assertEqual(m.ssl_statuses(self.db,self.user)['1']['status'],'secure')
        d.port=8729;self.db.commit();self.assertEqual(m.ssl_statuses(self.db,self.user)['1']['status'],'unknown')

if __name__=='__main__':unittest.main(verbosity=2)
