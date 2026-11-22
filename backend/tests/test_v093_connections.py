"""Device edit/create tests against SQLite, with simulated RouterOS connections."""
import unittest
from unittest.mock import patch
from fastapi import HTTPException
import test_device_management_routes as old
v=old.v

class Connections(unittest.TestCase):
    def setUp(self):
        self.f=old.Routes();self.f.setUp();self.f.user.role='admin';self.d=self.f.d
    def tearDown(self):self.f.tearDown()
    def update(self,**kw):return v.update_device(1,v.DeviceUpdate(**kw),self.f.db,self.f.user)
    def create(self,**kw):return v.create_device(v.DeviceCreate(host='192.0.2.2',username='test',password='dummy1234',**kw),self.f.db,self.f.user)
    def assertOld(self):self.assertEqual((self.d.port,self.d.use_tls,self.d.tls_fingerprint),(8728,False,None))
    def test_switch_standard_port(self):
        with patch.object(v,'fetch_identity',return_value='old') as probe:self.update(use_tls=True,tls_fingerprint='a'*64)
        calls=[x.args[0] for x in probe.call_args_list];self.assertEqual([x.port for x in calls],[8728,8729]);self.assertEqual([x.tls_fingerprint for x in calls],[None,'a'*64]);self.assertEqual(self.d.tls_fingerprint,'a'*64);self.assertEqual(self.f.db.query(v.DeviceManagementEvent).one().action,'tls-edit')
    def test_pin_required(self):
        with patch.object(v,'fetch_identity') as probe,self.assertRaises(HTTPException) as err:self.update(use_tls=True)
        self.assertEqual(err.exception.status_code,422);probe.assert_not_called();self.assertOld()
    def test_operator_cannot_switch(self):
        self.f.user.role='operator'
        with self.assertRaises(HTTPException) as err:self.update(use_tls=True,tls_fingerprint='a'*64)
        self.assertEqual(err.exception.status_code,403);self.assertOld()
    def test_pin_mismatch_retains_previous(self):
        with patch.object(v,'fetch_identity',side_effect=['old',RuntimeError('pin mismatch')]),self.assertRaises(HTTPException) as err:self.update(use_tls=True,tls_fingerprint='a'*64)
        self.assertEqual(err.exception.status_code,502);self.assertOld()
    def test_wrong_identity_retains_previous(self):
        with patch.object(v,'fetch_identity',side_effect=['old','other']),self.assertRaises(HTTPException):self.update(use_tls=True,tls_fingerprint='a'*64)
        self.assertOld()
    def test_custom_port_retained(self):
        self.d.port=18728;self.f.db.commit()
        with patch.object(v,'fetch_identity',return_value='old'):self.update(use_tls=True,tls_fingerprint='a'*64)
        self.assertEqual(self.d.port,18728)
    def test_pinned_downgrade_refused(self):
        self.d.port=8729;self.d.use_tls=True;self.d.tls_fingerprint='a'*64;self.f.db.commit()
        with patch.object(v,'fetch_identity') as probe,self.assertRaises(HTTPException) as err:self.update(use_tls=False)
        self.assertEqual(err.exception.status_code,409);probe.assert_not_called();self.assertTrue(self.d.use_tls)
    def test_pin_legacy_tls(self):
        self.d.port=8729;self.d.use_tls=True;self.f.db.commit()
        with patch.object(v,'fetch_identity',return_value='old') as probe:self.update(tls_fingerprint='a'*64)
        self.assertEqual(probe.call_count,1);self.assertEqual(probe.call_args.args[0].tls_fingerprint,'a'*64);self.assertEqual(self.d.tls_fingerprint,'a'*64)
    def test_metadata_edit_without_network(self):
        with patch.object(v,'fetch_identity') as probe:self.update(name='new');probe.assert_not_called()
        self.assertEqual(self.d.name,'new')
    def test_plain_port_change_requires_connection(self):
        with patch.object(v,'fetch_identity',side_effect=RuntimeError('offline')),self.assertRaises(HTTPException):self.update(port=54321)
        self.assertOld()
    def test_new_tls_pin_required(self):
        with self.assertRaises(HTTPException) as err:self.create(use_tls=True)
        self.assertEqual(err.exception.status_code,422);self.assertEqual(self.f.db.query(old.Device).count(),1)
    def test_new_tls_connects_before_create(self):
        with patch.object(v,'fetch_identity',return_value='new') as probe:d=self.create(use_tls=True,tls_fingerprint='a'*64)
        self.assertEqual(d.name,'new');self.assertEqual(d.identity,'new');self.assertEqual(d.port,8729);self.assertEqual(d.tls_fingerprint,'a'*64);self.assertEqual(probe.call_count,1)
    def test_new_tls_failed_not_inserted(self):
        with patch.object(v,'fetch_identity',return_value=None),self.assertRaises(HTTPException):self.create(use_tls=True,tls_fingerprint='a'*64)
        self.assertEqual(self.f.db.query(old.Device).count(),1)
    def test_plain_offline_registration_kept(self):
        with patch.object(v,'fetch_identity') as probe:d=self.create(name='offline',use_tls=False);probe.assert_not_called()
        self.assertEqual(d.port,8728)
    def test_project_version(self):
        from app.api.v1.health import version
        self.assertEqual(version()['version'],'0.8.9.1');self.assertEqual(version()['modules']['Device Manager'],'0.9.3.10');self.assertEqual(version()['modules']['Device Visualization'],'1.3')

if __name__=='__main__':unittest.main(verbosity=2)
