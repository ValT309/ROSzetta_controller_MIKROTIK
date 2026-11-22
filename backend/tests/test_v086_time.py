from datetime import datetime, timezone
import unittest
from test_management_jobs import FakeAPI, m
from app.services import time_management as t

class Clock(unittest.TestCase):
    def setUp(self):
        self.api=FakeAPI();self.api.rows[('system','clock')]=[{'date':'2026-11-20','time':'12:00:00','gmt-offset':'+03:00','time-zone-name':'Europe/Moscow'}]
        self.api.rows[('system','ntp','client')]=[{'enabled':False,'status':'stopped'}];self.api.rows[('system','ntp','client','servers')]=[]
    def test_offset(self):self.assertEqual(t.parse_clock(self.api.rows[('system','clock')][0]).hour,9)
    def test_old_format(self):self.assertEqual(t.parse_clock({'date':'nov/20/2026','time':'12:00:00','gmt-offset':'10800'}).hour,9)
    def test_epoch(self):
        self.api.rows[('system','clock')][0]['date']='1970-08-10'
        with self.assertRaises(t.TimeBlocked):t.require_clock(self.api)
        self.assertFalse(self.api.calls)
    def test_utc_match(self):self.assertTrue(t.clock_check(self.api,datetime(2026,11,20,9,tzinfo=timezone.utc))['clock_ok'])
    def test_unknown(self):
        self.api.rows[('system','clock')][0]['gmt-offset']=''
        with self.assertRaises(t.TimeBlocked):t.require_clock(self.api)
    def test_validate(self):self.assertEqual(t.validate(['10.0.0.1','10.0.0.1','ntp.example.org'],'Europe/Moscow')['servers'],['10.0.0.1','ntp.example.org'])
    def test_invalid(self):
        for s in ('','bad host','a;command'):
            with self.assertRaises(t.TimeBlocked):t.validate([s],'')
    def test_disabled_server(self):
        self.api.rows[('system','ntp','client','servers')]=[{'address':'10.0.0.1','disabled':True}]
        with self.assertRaises(t.TimeBlocked):t.configure(self.api,{'servers':['10.0.0.1'],'zone':''})
        self.assertFalse(self.api.calls)
    def test_audit_read_only(self):self.assertTrue(t.inspect(self.api)['attention']);self.assertFalse(self.api.calls)

class ApplyClock(Clock):
    def test_additive_write(self):
        self.api.rows[('system','ntp','client','servers')]=[{'address':'10.0.0.2','dynamic':True}]
        class Writable(FakeAPI):
            def __call__(self,cmd,**args):
                self.calls.append(cmd)
                if cmd=='/system/ntp/client/servers/add': self.rows[('system','ntp','client','servers')].append(args)
                elif cmd=='/system/ntp/client/set': self.rows[('system','ntp','client')][0].update(args)
                elif cmd=='/system/clock/set': self.rows[('system','clock')][0].update(args)
                return []
        api=Writable();api.rows=self.api.rows
        r=t.configure(api,{'servers':['10.0.0.1'],'zone':''});self.assertTrue(r['ntp_enabled']);self.assertEqual(set(r['servers']),{'10.0.0.1','10.0.0.2'})
        t.configure(api,{'servers':['10.0.0.1'],'zone':''});self.assertEqual(len(api.calls),2)

class Renew(unittest.TestCase):
    def test_active_controller_blocked(self):
        from types import SimpleNamespace
        a=FakeAPI()
        with self.assertRaises(m.Blocked):m.renew_expired_tls(a,SimpleNamespace(use_tls=True))
        self.assertFalse(a.calls)
    def test_unknown_certificate_blocked(self):
        from types import SimpleNamespace
        a=FakeAPI()
        with self.assertRaises(m.Blocked):m.renew_expired_tls(a,SimpleNamespace(use_tls=False))
        self.assertFalse(a.calls)
    def test_expired_leaf_rotation_preserves_acl(self):
        from types import SimpleNamespace
        class Writable(FakeAPI):
            def __call__(self,cmd,**args):
                if cmd=='/certificate/sign' and args.get('ca'):
                    self.calls.append((cmd,args))
                    r=next(x for x in self.rows[('certificate',)] if x['name']==args['number'])
                    r.update(fingerprint='b'*64,ca=args['ca'],**{'private-key':True,'trusted':False})
                    return []
                return super().__call__(cmd,**args)
        a=Writable(); old='roszetta-api-123456abcdef'; a.rows[('certificate',)]=[{'.id':'*c','name':old,'common-name':'10.0.0.6','fingerprint':'a'*64,'key-usage':'tls-server','expired':True,'private-key':True}]
        row=a.rows[('ip','service')][1];row.update(certificate=old,disabled=False,address='10.0.0.8/32')
        d=SimpleNamespace(use_tls=False,host='10.0.0.6')
        name,port,fp,before,after=m.renew_expired_tls(a,d)
        self.assertNotEqual(name,old);self.assertEqual(fp,'b'*64);self.assertEqual(after['address'],before['address']);self.assertEqual(port,8729)
        self.assertTrue(any(r['name']==old for r in a.rows[('certificate',)]))
        self.assertFalse(after['disabled'])
