import hashlib
import ssl
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.services.routeros import management as m

class PathMock:
    def __init__(self,api,path): self.api=api; self.path=path
    def __iter__(self): return iter(self.api.rows[self.path])
    def __call__(self,cmd,**args):
        self.api.calls.append((self.path,cmd,args.copy()))
        for row in self.api.rows[self.path]:
            if row.get('.id')==args.get('.id'): row.update(args)
        return []

class API:
    def __init__(self):
        self.rows={('ip','service'):[{'.id':'*1','name':'ssh','disabled':True,'port':22,'address':''},{'.id':'*2','name':'api-ssl','disabled':True,'port':8729,'address':'','certificate':'none'},{'.id':'*3','name':'api','disabled':False,'port':8728,'address':'10.1.1.1/32'},{'.id':'*9','name':'ssh','dynamic':True}],('certificate',):[{'name':'api-cert'}],('system','identity'):[{'name':'old'}]};self.calls=[]
    def path(self,*p): return PathMock(self,p)
    def __call__(self,**args): self.calls.append(args);self.rows[('system','identity')][0]['name']=args['name'];return []

class TestManagement(unittest.TestCase):
    def setUp(self):self.api=API()
    def test_enable_ssh(self):
        r=m.prepare_service(self.api,'ssh','10.110.0.109/32');self.assertEqual(r['address'],'10.110.0.109/32');self.assertFalse(m.truth(r['disabled']));self.assertEqual(len(self.api.calls),1)
    def test_keep_other_addresses(self):
        self.api.rows[('ip','service')][0]['address']='10.1.0.0/16,192.0.2.1';r=m.prepare_service(self.api,'ssh','10.110.0.109/32');self.assertEqual(r['address'],'10.1.0.0/16,192.0.2.1/32,10.110.0.109/32')
    def test_existing_subnet(self):
        self.api.rows[('ip','service')][0]['address']='10.110.0.0/24';r=m.prepare_service(self.api,'ssh','10.110.0.109/32');self.assertEqual(r['address'],'10.110.0.0/24')
    def test_reject_broad_source(self):
        with self.assertRaises(ValueError):m.prepare_service(self.api,'ssh','10.0.0.0/8')
        self.assertFalse(self.api.calls)
    def test_reject_live_unrestricted(self):
        self.api.rows[('ip','service')][0]['disabled']=False
        with self.assertRaises(ValueError):m.prepare_service(self.api,'ssh','10.110.0.109/32')
        self.assertFalse(self.api.calls)
    def test_reject_any_rule(self):
        self.api.rows[('ip','service')][0]['address']='0.0.0.0/0'
        with self.assertRaises(ValueError):m.prepare_service(self.api,'ssh','10.110.0.109/32')
        self.assertFalse(self.api.calls)
    def test_no_certificate(self):
        with self.assertRaises(ValueError):m.prepare_service(self.api,'api-ssl','10.110.0.109/32')
        self.assertFalse(self.api.calls)
    def test_prepare_ssl(self):
        r=m.prepare_service(self.api,'api-ssl','10.110.0.109/32','api-cert');self.assertEqual(r['certificate'],'api-cert');self.assertEqual(self.api.rows[('ip','service')][2]['disabled'],False)
    def test_no_live_cert_replace(self):
        self.api.rows[('ip','service')][1].update(disabled=False,address='10.110.0.109/32',certificate='old')
        with self.assertRaises(ValueError):m.prepare_service(self.api,'api-ssl','10.110.0.109/32','api-cert')
        self.assertFalse(self.api.calls)
    def test_no_api_write(self):
        with self.assertRaises(ValueError):m.prepare_service(self.api,'api','10.110.0.109/32')
        self.assertFalse(self.api.calls)
    def test_rename(self):
        m.rename_identity(self.api,'new');self.assertEqual(self.api.rows[('system','identity')][0]['name'],'new')
    def test_pin_match(self):
        from unittest.mock import Mock
        ctx=Mock();sock=Mock();tls=ctx.wrap_socket.return_value;tls.getpeercert.return_value=b'test-cert'
        self.assertIs(m.pinned_wrapper(ctx,hashlib.sha256(b'test-cert').hexdigest())(sock),tls);tls.close.assert_not_called()
    def test_pin_mismatch(self):
        from unittest.mock import Mock
        ctx=Mock();tls=ctx.wrap_socket.return_value;tls.getpeercert.return_value=b'other-cert'
        with self.assertRaises(ssl.SSLError):m.pinned_wrapper(ctx,'0'*64)(Mock())
        tls.close.assert_called_once()
    def test_missing_certificate(self):
        from unittest.mock import Mock
        ctx=Mock();tls=ctx.wrap_socket.return_value;tls.getpeercert.return_value=None
        with self.assertRaises(ssl.SSLError):m.pinned_wrapper(ctx,'0'*64)(Mock())
        tls.close.assert_called_once()
if __name__=='__main__':unittest.main()
