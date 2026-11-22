import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('port_network',Path(__file__).resolve().parents[1]/'app/services/routeros/port_network.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class PortNetworkTests(unittest.TestCase):
    def setUp(self):
        self.t={'interfaces':[{'name':'uplink','type':'ether'}], 'bridges':[{'name':'br','vlan-filtering':True}], 'ports':[{'interface':'uplink','bridge':'br','pvid':20,'hw':True}], 'vlans':[{'bridge':'br','vlan-ids':20,'current-tagged':'','current-untagged':'uplink'}]}
    def result(self,errors=None):return m.summarize(self.t,errors or {},'uplink')
    def test_access(self): self.assertEqual(self.result()['mode'],'access')
    def test_hybrid(self):
        self.t['vlans'].append({'bridge':'br','vlan-ids':[30,40],'current-tagged':'uplink','current-untagged':''});r=self.result();self.assertEqual(r['mode'],'hybrid');self.assertEqual(r['vlans'][1]['ids'],'30,40')
    def test_trunk(self):
        self.t['vlans'][0].update({'current-tagged':'uplink','current-untagged':''});self.assertEqual(self.result()['mode'],'trunk')
    def test_no_vlan_filtering(self):
        self.t['bridges'][0]['vlan-filtering']=False;self.assertEqual(self.result()['mode'],'unfiltered')
    def test_config_not_actual(self):
        self.t['vlans']=[{'bridge':'br','vlan-ids':20,'untagged':'uplink'}];r=self.result();self.assertEqual(r['mode'],'unknown');self.assertFalse(r['vlans'][0]['actual'])
    def test_partial(self): self.assertEqual(self.result({'vlans':'failed'})['mode'],'unknown')
    def test_hw_config_not_fact(self):
        r=self.result()['bridge'];self.assertTrue(r['hw_configured']);self.assertIsNone(r['hw_active'])
    def test_no_bridge(self):
        self.t['ports']=[];self.assertEqual(self.result()['mode'],'no_bridge');self.assertEqual(self.result({'ports':'failed'})['mode'],'unknown')
    def test_no_prefix_match(self):
        self.t['vlans'][0]['current-untagged']='uplink2';self.assertEqual(self.result()['vlans'],[])
    def test_other_bridge(self):
        self.t['vlans'][0]['bridge']='other';self.assertEqual(self.result()['vlans'],[])
    def test_neighbor_composite(self):
        self.t['neighbors']=[{'interface':'br/uplink','address':'10.1.1.2'},{'interface':'br','address':'10.1.1.3'}];self.assertEqual([n['ip'] for n in self.result()['neighbors']],['10.1.1.2'])
    def test_mac_arp(self):
        self.t['hosts']=[{'mac-address':'aa:bb:cc:dd:ee:ff','on-interface':'uplink','vid':20},{'mac-address':'aa:bb:cc:dd:ee:01','on-interface':'uplink','local':True}];self.t['arp']=[{'mac-address':'AA:BB:CC:DD:EE:FF','address':'10.1.1.2','interface':'vlan20'},{'mac-address':'AA:BB:CC:DD:EE:FF','address':'10.1.1.3','complete':False}];r=self.result();self.assertEqual(r['host_count'],1);self.assertEqual(r['hosts'][0]['ip_candidates'][0]['interface'],'vlan20');self.assertEqual(len(r['hosts'][0]['ip_candidates']),1)
    def test_bond(self):
        self.t['bonds']=[{'name':'bond1','slaves':'uplink,ether2'}];self.t['ports'][0]['interface']='bond1';self.t['vlans'][0]['current-untagged']='bond1';r=self.result();self.assertEqual(r['bridge']['member'],'bond1');self.assertEqual(r['bonding'],['bond1'])
    def test_direct_vlan(self):
        self.t['vlan_interfaces']=[{'name':'v20','interface':'uplink','vlan-id':20},{'name':'v30','interface':'other','vlan-id':30}];self.assertEqual(len(self.result()['vlan_interfaces']),1)
    def test_truncated(self):
        self.t['hosts']=[{'mac-address':'aa:bb:cc:dd:ee:ff','on-interface':'uplink'}]*201;r=self.result();self.assertTrue(r['truncated']);self.assertEqual(len(r['hosts']),200)
    def test_invalid_interface(self):
        with self.assertRaises(ValueError):m.summarize(self.t,{},'other')
    def test_disabled_record(self):
        self.t['vlans'][0]['disabled']='yes';self.assertEqual(self.result()['vlans'],[])
if __name__=='__main__':unittest.main()
