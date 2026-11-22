import ast
import importlib.util
from pathlib import Path
from contextlib import contextmanager
import unittest
from unittest.mock import patch
import time

root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('topology_graph',root/'app/services/routeros/topology_graph.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

def node(i, name=None): return dict(id=f'd{i}',label=name or f'n{i}',host=f'192.0.2.{i}')
def sample(i): return dict(macs=[f'02:00:00:00:00:{i:02x}'],ports={'p1':{'speed':'1G','running':True},'p2':{'speed':'10G','running':True}},neighbors=[],fdb=[])
def nb(i,p='p1',q='p1',proto='lldp'):return dict(mac=f'02:00:00:00:00:{i:02x}',interface=p,remote_port=q,protocol=proto)

class Graph(unittest.TestCase):
    def setUp(self): self.nodes=[node(i) for i in (1,2,3)];self.s={f'd{i}':sample(i) for i in (1,2,3)}
    def edges(self,fdb=False):return g.build_edges(self.nodes,self.s,fdb)
    def test_reciprocal(self):
        self.s['d1']['neighbors']=[nb(2)];self.s['d2']['neighbors']=[nb(1)]
        e,=self.edges();self.assertEqual((e['evidence'],e['speed'],e['link_state']),('confirmed','1G','up'))
    def test_single(self):
        self.s['d1']['neighbors']=[nb(2)];e,=self.edges();self.assertEqual(e['evidence'],'probable')
    def test_mndp_is_not_direct_proof(self):
        self.s['d1']['neighbors']=[nb(2,proto='mndp')];self.s['d2']['neighbors']=[nb(1,proto='mndp')];self.assertEqual(self.edges()[0]['evidence'],'neighbor')
    def test_parallel(self):
        self.s['d1']['neighbors']=[nb(2),nb(2,'p2','p2')];self.s['d2']['neighbors']=[nb(1),nb(1,'p2','p2')];es=self.edges();self.assertEqual(len(es),2);self.assertTrue(all(e['evidence']=='confirmed' for e in es))
    def test_ambiguous_not_confirmed(self):
        self.s['d1']['neighbors']=[nb(2,q=None)];self.s['d2']['neighbors']=[nb(1,q=None),nb(1,'p2',None)];self.assertFalse(any(e['evidence']=='confirmed' for e in self.edges()))
    def test_conflicting_mac_identity(self):
        self.s['d1']['neighbors']=[dict(nb(2),identity='n3')];self.assertEqual(self.edges(),[])
    def test_duplicate_identity(self):
        self.nodes[1]['label']=self.nodes[2]['label']='shared';self.s['d1']['neighbors']=[dict(interface='p1',identity='shared')];self.assertEqual(self.edges(),[])
    def test_composite_port(self):
        self.s['d1']['neighbors']=[nb(2,'bridge/p2','p2')];self.assertEqual(self.edges()[0]['a_port'],'p2')
    def test_logical_port(self):
        self.s['d1']['neighbors']=[nb(2,'vlan20')];self.s['d2']['neighbors']=[nb(1)];self.assertTrue(all(e['evidence']!='confirmed' for e in self.edges()))
    def test_fdb_optin(self):
        self.s['d1']['fdb']=[dict(mac=self.s['d2']['macs'][0],port='p1')];self.assertEqual(self.edges(),[]);e,=self.edges(True);self.assertEqual(e['evidence'],'fdb')
    def test_fdb_ambiguous(self):
        self.s['d1']['fdb']=[dict(mac=self.s['d2']['macs'][0],port=p) for p in ('p1','p2')];self.assertEqual(self.edges(True),[])
    def test_fdb_shared_mac(self):
        self.s['d3']['macs']=self.s['d2']['macs'];self.s['d1']['fdb']=[dict(mac=self.s['d2']['macs'][0],port='p1')];self.assertEqual(self.edges(True),[])
    def test_neighbor_supersedes_fdb(self):
        self.s['d1']['neighbors']=[nb(2)];self.s['d1']['fdb']=[dict(mac=self.s['d2']['macs'][0],port='p2')];self.assertEqual(len(self.edges(True)),1)
    def test_speed_conflict(self):
        self.s['d1']['neighbors']=[nb(2,'p1','p2')];e,=self.edges();self.assertTrue(e['speed_conflict']);self.assertIsNone(e['speed'])
    def test_down(self):
        self.s['d1']['ports']['p1']['running']=False;self.s['d1']['neighbors']=[nb(2)];self.assertEqual(self.edges()[0]['link_state'],'down')
    def test_missing_remote_not_physical(self):
        self.s['d1']['neighbors']=[nb(2,q=None)];self.s['d2']['neighbors']=[nb(1,q=None)]
        e,=self.edges();self.assertEqual(e['evidence'],'neighbor')
    def test_competing_reciprocal_ports(self):
        self.s['d1']['neighbors']=[nb(2),nb(3)];self.s['d2']['neighbors']=[nb(1)];self.s['d3']['neighbors']=[nb(1)]
        self.assertFalse(any(e['evidence']=='confirmed' for e in self.edges()))
    def test_cross_protocol_not_physical(self):
        self.s['d1']['neighbors']=[nb(2,proto='lldp')];self.s['d2']['neighbors']=[nb(1,proto='cdp')]
        self.assertEqual(self.edges()[0]['evidence'],'probable')
    def test_composite_physical(self):
        self.s['d1']['neighbors']=[nb(2,'p1,bridge1','bridge1/p1','cdp,lldp,mndp')];self.s['d2']['neighbors']=[nb(1,'p1,bridge1','bridge1/p1','cdp,lldp,mndp')]
        self.assertEqual(self.edges()[0]['evidence'],'confirmed')
    def test_logical_collapsed(self):
        self.s['d1']['neighbors']=[nb(2,proto='cdp,mndp'),nb(2,'p2','p2',proto='cdp,mndp')];self.s['d2']['neighbors']=[nb(1,'p2',None,proto='mndp')]
        e,=self.edges();self.assertEqual(e['evidence'],'neighbor');self.assertIsNone(e['a_port'])
    def test_exact_survives_missing_remote_duplicate(self):
        self.s['d1']['neighbors']=[nb(2),nb(2,q=None)];self.s['d2']['neighbors']=[nb(1)]
        e,=self.edges();self.assertEqual(e['evidence'],'confirmed')
    def test_shared_segment_lldp_wins(self):
        self.s['d1']['neighbors']=[nb(2,'p1,bridge1','bridge1/p1','cdp,lldp,mndp'),nb(3,'p1,bridge1','bridge/p1','cdp,mndp')]
        self.s['d2']['neighbors']=[nb(1,'p1,bridge1','bridge1/p1','cdp,lldp,mndp'),nb(3,'p2,bridge1','bridge/p1','lldp')]
        self.s['d3']['neighbors']=[nb(1,'p1','p1','cdp,mndp')]
        physical=[e for e in self.edges() if e['evidence'] in ('confirmed','probable')]
        self.assertEqual({(e['a'],e['b'],e['evidence']) for e in physical},{('d1','d2','confirmed'),('d2','d3','probable')})
    def test_alias(self):
        self.s['d2']['ports']['p1']['default_name']='ether1'
        self.s['d1']['neighbors']=[nb(2,'p1,bridge1','bridge/ether1')]
        self.assertEqual(self.edges()[0]['b_port'],'p1')
    def test_vlan_context(self):
        self.s['d1']['logical']={'vlan111':'vlan'}
        self.s['d1']['neighbors']=[nb(2,'p1,vlan111','p1')]
        self.assertEqual(self.edges()[0]['evidence'],'neighbor')
    def test_vpn_not_physical(self):
        self.s['d1']['neighbors']=[nb(2,'<l2tp-site>','l2tp-out1','mndp')]
        self.assertEqual(self.edges()[0]['evidence'],'vpn')
    def test_unmanaged_conflict(self):
        self.s['d1']['neighbors']=[nb(2),dict(interface='p1,bridge',identity='external',protocol='lldp',remote_port='ether1',mac='02:00:00:00:00:ff')]
        self.assertEqual(self.edges()[0]['evidence'],'neighbor')
        self.assertEqual(g.unmanaged_lldp(self.nodes,self.s)[0]['identity'],'external')
    def test_invalid_mac(self):self.assertIsNone(g.mac('noise 02:00:00:00:00:02'))
    def test_no_duplicate_unknown_ports(self):
        self.s['d1']['neighbors']=[nb(2,'bridge','bridge')];self.s['d2']['neighbors']=[nb(1,'bridge','bridge')];self.assertEqual(len(self.edges()),1)

# Load the real collector without opening a database or RouterOS socket.
src=root/'app/api/v1/topology.py'
class Fake:
    def __init__(self,fail=False): self.fail=fail;self.calls=[]
    def path(self,*parts):
        self.calls.append(parts)
        if parts==('interface',):return [{'name':'p1','type':'ether','running':True,'rx-byte':'90071992547409930','tx-byte':12,'mac-address':'02:00:00:00:00:01'},{'name':'bridge','type':'bridge'}]
        if parts==('system','resource'):return [{'uptime':'1d'}]
        if parts==('ip','neighbor'):
            if self.fail:raise RuntimeError('not supported')
            return [{'interface':'p1','discovered-by':'lldp','interface-name':'p2','mac-address':'02:00:00:00:00:02'}]
        if parts==('interface','ethernet'):return [{'.id':'*1','name':'p1'}]
        if parts==('interface','bridge','host'):return [{'mac-address':'02:00:00:00:00:02','on-interface':'p1','dynamic':True},{'mac-address':'02:00:00:00:00:03','on-interface':'p1','dynamic':False}]
        raise AssertionError(parts)
    def __call__(self,cmd,**kw):
        self.calls.append((cmd,kw));assert cmd=='/interface/ethernet/monitor' and 'once' in kw
        return [{'name':'p1','status':'link-ok','rate':'1Gbps'}]

@contextmanager
def session(api):yield api
ns={'routeros_session':session,'time':time,'_normalize_link_rate':lambda s:'1G' if s=='1Gbps' else None,'parse_uptime':lambda s:86400 if s=='1d' else None}
exec(compile(ast.Module(body=[n for n in ast.parse(src.read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='_collect'],type_ignores=[]),str(src),'exec'),ns)
collect=ns['_collect']
class Collector(unittest.TestCase):
    def test_regular(self):
        api=Fake();r=collect(api,None,False);self.assertIsNone(r['error']);self.assertEqual(r['ports']['p1']['rx'],'90071992547409930');self.assertEqual(r['ports']['p1']['speed'],'1G');self.assertNotIn('bridge',r['ports']);self.assertNotIn(('interface','bridge','host'),api.calls)
    def test_fdb_only_learned(self):self.assertEqual(len(collect(Fake(),None,True)['fdb']),1)
    def test_partial(self):
        r=collect(Fake(True),None,False);self.assertTrue(r['error']);self.assertIn('p1',r['ports'])
    def test_no_credentials(self):self.assertEqual(collect(None,'locked',False)['error'],'locked')

if __name__=='__main__':unittest.main()
