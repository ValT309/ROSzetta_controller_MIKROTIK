import unittest
from types import SimpleNamespace as N
from app.services.routeros_generator import generate


def port(name, role, pvid='1'):
    return N(name=name,role=role,pvid=pvid)

def vlan(i='60',subnet='10.180.16.0/24',gateway='10.180.16.1',tagged='ether3',untagged=''):
    return N(id=i,name='test',subnet=subnet,gateway=gateway,dhcp=False,poolStart='',poolEnd='',tagged=tagged,untagged=untagged)

def native(**kw):
    d=dict(enabled=True,pvid='1',address='10.180.10.1/23',dhcp=True,poolStart='10.180.10.20',poolEnd='10.180.11.250',ospf=True)
    d.update(kw)
    return N(**d)

class BridgeTests(unittest.TestCase):
    def run_case(self, b=None, ports=None, vlans=None, split=True, wan='', guests=(), wifi=(), model='hAP ax²'):
        return generate(ports if ports is not None else [port('ether1','wan'),port('ether2','lan')],vlans or [],'77.88.8.8,8.8.4.4','ether1',model,wifi,split,guests,b or native(),wan)
    def test_bridge_only(self):
        r=self.run_case(); self.assertEqual(r['errors'],[]); c=r['config']; self.assertIn('frame-types=admit-all pvid=1',c); self.assertIn('vlan-ids=1 untagged=bridge-lan,ether2',c); self.assertIn('address=10.180.10.1/23 interface=bridge-lan',c); self.assertNotIn('/interface vlan add',c); self.assertIn('gateway=10.180.10.1 dns-server=10.180.10.1',c); self.assertTrue(c.endswith('vlan-filtering=yes'))
    def test_hybrid_native_and_tagged(self):
        r=self.run_case(ports=[port('ether1','wan'),port('ether2','lan'),port('ether3','hybrid')],vlans=[vlan()]); self.assertEqual(r['errors'],[]); c=r['config']; self.assertIn('vlan-ids=1 untagged=bridge-lan,ether2,ether3',c);self.assertIn('vlan-ids=60 tagged=bridge-lan,ether3',c);self.assertIn('interface=ether3 pvid=1 ingress-filtering=yes frame-types=admit-all',c)
    def test_native_nondefault_pvid_rb5009(self):
        r=self.run_case(native(pvid='130',dhcp=False),ports=[port('ether1','wan'),port('ether8','lan','130')],model='RB5009');self.assertEqual(r['errors'],[]);self.assertIn('vlan-ids=130 untagged=bridge-lan,ether8',r['config']);self.assertNotIn('dhcp-server add',r['config'])
    def test_bridge_public_dns(self):
        r=self.run_case(split=False);self.assertEqual(r['errors'],[]); self.assertIn('dns-server=77.88.8.8,8.8.4.4',r['config'])
    def test_duplicate_native_id(self):
        r=self.run_case(ports=[port('ether1','wan'),port('ether2','lan'),port('ether3','trunk')],vlans=[vlan(i='1')]);self.assertTrue(r['errors']);self.assertEqual(r['config'],'')
    def test_overlaps_vlan(self):
        r=self.run_case(ports=[port('ether1','wan'),port('ether2','lan'),port('ether3','trunk')],vlans=[vlan(subnet='10.180.11.0/24',gateway='10.180.11.1')]);self.assertTrue(any('пересечение' in e for e in r['errors']))
    def test_overlaps_wan(self):
        self.assertTrue(self.run_case(wan='10.180.11.50/24')['errors'])
    def test_native_no_access_port(self):
        self.assertTrue(self.run_case(ports=[port('ether1','wan')])['errors'])
    def test_bad_address_pool_and_pvid(self):
        for b in [native(address='10.180.10.0/23'),native(address='10.180.10.1'),native(poolStart='10.180.10.1'),native(poolEnd='10.180.12.50'),native(pvid='4095')]:
            with self.subTest(b=b):self.assertTrue(self.run_case(b)['errors'])
    def test_guest_or_wifi_conflict(self):
        self.assertTrue(self.run_case(guests=[1])['errors']);self.assertTrue(self.run_case(wifi=[1])['errors'])
    def test_disabled_is_backward_compatible(self):
        ports=[port('ether1','wan'),port('ether3','trunk')]; vs=[vlan()]; a=generate(ports,vs,'77.88.8.8,8.8.4.4','ether1','hAP ax²');b=generate(ports,vs,'77.88.8.8,8.8.4.4','ether1','hAP ax²',bridge=native(enabled=False));self.assertEqual(a,b);self.assertIn('frame-types=admit-only-vlan-tagged',b['config'])

if __name__=='__main__':unittest.main()
