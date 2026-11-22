import os
import unittest
from uuid import uuid4
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
os.environ.setdefault('DATABASE_URL','sqlite://')
from app.core.db import Base, get_db
from app.models.user import User
from app.models.object_site import ObjectSite
from app.api.deps import get_current_user
from app.api.v1.object_constructor import router, Services, BridgeLan
from app.services.vault import vault_service


def draft():
    return dict(bridgeLan=BridgeLan().model_dump(),profile='office',name='TEST',model='hAP ax²',identity='',wanMode='pppoe',wanPort='ether1',pppoeUser='test',pppoePassword='SECRET_PPP_TEST',wanAddress='',wanGateway='',ports=[],vlans=[],dns='',l2tp=[dict(enabled=False,name=f'l2tp-{i}',server='',user='',password='SECRET_L2TP_TEST',ipsecSecret='SECRET_PSK_TEST',ospfKey='SECRET_OSPF_TEST',cost='10') for i in (1,2)],loopbackAddress='',ospfRouterId='',ospfArea='backbone',firewallProfile='standard',management='',guests='',corporate='',wifiEnabled=False,wifiSsid='',wifiPassword='SECRET_WIFI_TEST',services=Services().model_dump())

class SiteTests(unittest.TestCase):
    def setUp(self):
        self.engine=create_engine('sqlite://',connect_args={'check_same_thread':False},poolclass=StaticPool)
        Base.metadata.create_all(self.engine)
        self.Session=sessionmaker(bind=self.engine)
        with self.Session() as db:
            db.add_all([User(id=1,email='one',hashed_password='x',role='operator'),User(id=2,email='two',hashed_password='x',role='admin'),User(id=3,email='three',hashed_password='x',role='viewer')]);db.commit()
            vault_service.init_master_password(db,'unit-test-password')
        self.uid=1
        def session():
            with self.Session() as db: yield db
        def user():
            with self.Session() as db: return db.get(User,self.uid)
        app=FastAPI();app.include_router(router);app.dependency_overrides[get_db]=session;app.dependency_overrides[get_current_user]=user
        self.client=TestClient(app); self.id=str(uuid4());self.url='/sites/'+self.id
    def tearDown(self):
        self.client.close();vault_service.lock();self.engine.dispose()
    def save(self, revision=0, **changes):
        return self.client.put(self.url,json={'revision':revision,'draft':{**draft(),**changes}})
    def test_create_incomplete_draft(self):
        r=self.save(name='');self.assertEqual(r.status_code,200,r.text);self.assertEqual(r.json()['revision'],1);self.assertEqual(self.client.get(self.url).json()['draft']['name'],'')
    def test_encryption_and_list(self):
        self.assertEqual(self.save().status_code,200)
        with self.Session() as db:
            row=db.scalar(select(ObjectSite)); self.assertTrue(row.payload_enc.startswith('v2:'));self.assertNotIn('SECRET_',row.payload_enc)
        r=self.client.get('/sites');self.assertNotIn('SECRET_',r.text);self.assertNotIn('payload_enc',r.text); self.assertEqual(self.client.get(self.url).json()['draft'],draft())
    def test_update_conflict(self):
        self.assertEqual(self.save().status_code,200);self.assertEqual(self.save(1,name='updated').json()['revision'],2);self.assertEqual(self.save(1).status_code,409);self.assertEqual(self.client.get(self.url).json()['draft']['name'],'updated')
    def test_ownership_and_viewer(self):
        self.save();self.uid=2;self.assertEqual(self.client.get('/sites').json(),[]);self.assertEqual(self.client.get(self.url).status_code,404);self.assertEqual(self.save(1).status_code,409);self.assertEqual(self.client.delete(self.url,params={'revision':1}).status_code,409);self.uid=3;self.assertEqual(self.client.get('/sites').status_code,403)
    def test_locked_vault(self):
        self.save();vault_service.lock();self.assertEqual(self.client.get(self.url).status_code,423);self.assertEqual(self.save(1).status_code,423);self.assertEqual(self.client.get('/sites').status_code,200)
    def test_delete(self):
        self.save();self.assertEqual(self.client.delete(self.url,params={'revision':0}).status_code,409);self.assertEqual(self.client.delete(self.url,params={'revision':1}).status_code,204);self.assertEqual(self.client.get('/sites').json(),[])
    def test_invalid_payload_redacted(self):
        r=self.save(l2tp=[{'password':'SECRET_INVALID'}]);self.assertEqual(r.status_code,422);self.assertNotIn('SECRET_',r.text)
    def test_unlock_restores(self):
        self.save();vault_service.lock();
        with self.Session() as db: vault_service.unlock(db,'unit-test-password')
        self.assertEqual(self.client.get(self.url).json()['draft'],draft())
    def test_history_and_restore(self):
        self.assertEqual(self.save(loopbackAddress='10.0.0.50').status_code,200)
        self.assertEqual(self.save(1, name='new',loopbackAddress='10.0.0.51').status_code,200)
        versions=self.client.get(self.url+'/versions').json();self.assertEqual([v['revision'] for v in versions],[2,1])
        old=self.client.get(self.url+'/versions/1').json()['draft'];self.assertEqual(old['loopbackAddress'],'10.0.0.50')
        self.assertEqual(self.client.put(self.url,json={'revision':2,'draft':old}).json()['revision'],3)
        self.assertEqual(self.client.get(self.url).json()['draft'],old)
    def test_version_access(self):
        self.save();self.uid=2;self.assertEqual(self.client.get(self.url+'/versions').status_code,404);self.assertEqual(self.client.get(self.url+'/versions/1').status_code,404)
        self.uid=1;vault_service.lock();self.assertEqual(self.client.get(self.url+'/versions/1').status_code,423)
    def test_old_draft_defaults_and_history(self):
        self.save()
        with self.Session() as db:
            from app.models.object_site import ObjectSiteVersion
            row=db.get(ObjectSite,self.id);d=draft();d.pop('loopbackAddress');d.pop('bridgeLan');import json
            row.payload_enc=vault_service.encrypt_secret(json.dumps(d));db.query(ObjectSiteVersion).delete();db.commit()
        self.assertEqual(self.client.get(self.url).json()['draft']['loopbackAddress'],'')
        self.assertEqual(self.client.get(self.url).json()['draft']['bridgeLan'],BridgeLan().model_dump())
        self.assertEqual(self.save(1,name='new').status_code,200)
        self.assertEqual(self.client.get(self.url+'/versions/1').json()['draft']['loopbackAddress'],'')
    def test_loopback_unique_across_owners(self):
        self.assertEqual(self.save(loopbackAddress='10.0.0.50/32').status_code,200)
        self.uid=2;self.url='/sites/'+str(uuid4())
        r=self.save(loopbackAddress='10.0.0.50');self.assertEqual(r.status_code,409);self.assertEqual(r.json()['detail'],'Loopback already assigned')
        self.assertEqual(self.save(loopbackAddress='10.0.0.51').status_code,200)
    def test_services_encrypted_roundtrip(self):
        services=Services(radiusSecret='SECRET_RADIUS_TEST',snmpAuthPassword='SECRET_SNMP_TEST').model_dump()
        self.assertEqual(self.save(services=services).status_code,200)
        self.assertEqual(self.client.get(self.url).json()['draft']['services'],services)
        with self.Session() as db: self.assertNotIn('SECRET_RADIUS_TEST',db.scalar(select(ObjectSite)).payload_enc)
    def test_bridge_roundtrip_and_restore(self):
        b=BridgeLan(enabled=True,address='10.180.10.1/23',dhcp=True,poolStart='10.180.10.20',poolEnd='10.180.11.250').model_dump()
        self.assertEqual(self.save(bridgeLan=b).status_code,200)
        self.assertEqual(self.client.get(self.url).json()['draft']['bridgeLan'],b)
        self.assertEqual(self.save(1,bridgeLan=BridgeLan().model_dump()).status_code,200)
        old=self.client.get(self.url+'/versions/1').json()['draft']
        self.assertEqual(old['bridgeLan'],b)
        self.assertEqual(self.client.put(self.url,json={'revision':2,'draft':old}).status_code,200)
        self.assertEqual(self.client.get(self.url).json()['draft']['bridgeLan'],b)
if __name__=='__main__': unittest.main()
