"""Exercise the real helper with a fake RouterOS API; no network or DB."""
import ast
from pathlib import Path
import unittest
from typing import Any

source = Path(__file__).resolve().parents[1] / 'app/services/routeros/client.py'
class Logger:
    def debug(self, *args): pass
ns = {'Any': Any, 'logger': Logger()}
tree = ast.parse(source.read_text())
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {'_normalize_link_rate','_fetch_ethernet_link_speeds'}], type_ignores=[]), str(source), 'exec'), ns)
fetch = ns['_fetch_ethernet_link_speeds']
class FakeAPI:
    def __init__(self, fails=False): self.fails=fails; self.calls=0
    def path(self, *parts):
        self.calls += 1
        assert parts == ('interface','ethernet')
        return [{'name':'WAN','.id':'*1','default-name':'ether1'},{'name':'LAN','.id':'*2','default-name':'ether2'},{'name':'sfp','.id':'*3'}]
    def __call__(self, **kwargs):
        self.calls += 1
        if self.fails: raise RuntimeError('monitor failed')
        return [{'name':'WAN','rate':'2.5Gbps','status':'link-ok'},{'name':'LAN','status':'no-link'},{'name':'sfp','rate':'10Gbps'}]
class Tests(unittest.TestCase):
    def test_names_and_speeds(self):
        api=FakeAPI(); names={}
        self.assertEqual(fetch(api,names),{'WAN':'2.5G','LAN':None,'sfp':'10G'})
        self.assertEqual(names,{'WAN':'ether1','LAN':'ether2'})
        self.assertEqual(api.calls,2)
    def test_names_survive_monitor_failure(self):
        names={}; self.assertEqual(fetch(FakeAPI(True),names),{}); self.assertEqual(names['WAN'],'ether1')
    def test_old_signature(self): self.assertEqual(fetch(FakeAPI())['sfp'],'10G')
if __name__=='__main__': unittest.main()
