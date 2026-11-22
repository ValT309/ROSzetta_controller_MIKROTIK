import importlib.util, sys, types, unittest
from pathlib import Path
pkg=types.ModuleType('mode_test');pkg.__path__=[];sys.modules['mode_test']=pkg
client=types.ModuleType('mode_test.client');client.RouterOSError=RuntimeError;client.routeros_session=lambda c: None;sys.modules[client.__name__]=client
spec=importlib.util.spec_from_file_location('mode_test.device_mode',Path(__file__).resolve().parents[1]/'app/services/routeros/device_mode.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class API:
    def __init__(self,row): self.row=row
    def path(self,*args):
        assert args==('system','device-mode')
        if self.row is None: raise RuntimeError('not supported')
        return [self.row]
class Tests(unittest.TestCase):
    def test_bool(self):
        for v in ('yes',True,1): self.assertIs(m.boolean(v),True)
        for v in ('no',False,0): self.assertIs(m.boolean(v),False)
        self.assertIsNone(m.boolean(None))
    def test_read(self):
        r=m.read_mode(API({'mode':'home','fetch':'no','flagged':False,'allowed-versions':'7.13+'}));self.assertEqual(r['mode'],'home');self.assertIs(r['features']['fetch'],False);self.assertIsNone(r['features']['scheduler'])
    def test_unknown(self): self.assertEqual(m.read_mode(API(None))['status'],'unknown')
    def test_block_fetch(self): self.assertRaisesRegex(RuntimeError,'fetch=no',m.guard_mode,API({'fetch':False}),'fetch')
    def test_flagged(self): self.assertRaisesRegex(RuntimeError,'flagged=yes',m.guard_mode,API({'flagged':True}),None,True)
    def test_unknown_legacy(self): self.assertEqual(m.guard_mode(API(None),'fetch')['status'],'unknown')
    def test_internet_independent_fetch(self): self.assertEqual(m.guard_mode(API({'fetch':False}),block_flagged=True)['status'],'ok')
if __name__=='__main__':unittest.main()
