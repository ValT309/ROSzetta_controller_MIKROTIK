import unittest
from app.services.object_preflight import inspect_router

class FakeAPI:
    def __init__(self, existing=False, version='7.20.1'):
        self.existing=existing; self.version=version;self.paths=[]
    def path(self,*path):
        self.paths.append(path)
        return {('system','resource'):[{'board-name':'hAP ax2','version':self.version}],('system','identity'):[{'name':'LAB'}],('interface',):[{'name':'ether1','type':'ether'},{'name':'ether2','type':'ether'},{'name':'bridge-lan','type':'bridge'}],('interface','bridge'):[{}] if self.existing else [],('interface','wifi'):[{},{}]}.get(path,[])

class TestPreflight(unittest.TestCase):
    def test_clean(self):
        a=FakeAPI();r=inspect_router(a,'hAP ax²',['ether1','ether2'],True,True)
        self.assertTrue(all(c['ok'] for c in r['checks']));self.assertIn(('ip','dns','forwarders'),a.paths)
    def test_existing_and_mismatch(self):
        r=inspect_router(FakeAPI(True,'6.49'),'RB5009',['ether9','bridge-lan'])
        self.assertFalse(any(c['ok'] for c in r['checks']))
    def test_unknown_model(self):
        r=inspect_router(FakeAPI(),'Другая RouterOS 7',['ether1']);self.assertFalse(r['checks'][1]['ok'])
    def test_missing_features(self):
        class Missing(FakeAPI):
            def path(self,*p):
                if p in [('ip','dns','forwarders'),('interface','wifi')]:raise RuntimeError('missing')
                return super().path(*p)
        r=inspect_router(Missing(),'hAP ax²',['ether1'],True,True);self.assertFalse(r['checks'][-1]['ok']);self.assertFalse(r['checks'][-2]['ok'])

    def test_board_caret(self):
        class Caret(FakeAPI):
            def path(self,*p):
                if p==('system','resource'):return [{'board-name':'hAP ax^2','version':'7.23.7'}]
                return super().path(*p)
        self.assertTrue(inspect_router(Caret(),'hAP ax²',['ether1'])['checks'][1]['ok'])
