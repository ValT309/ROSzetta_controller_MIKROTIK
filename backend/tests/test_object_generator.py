import unittest
from types import SimpleNamespace as N
from app.services.routeros_generator import generate

class NetworkTests(unittest.TestCase):
    def run_case(self, model='hAP ax²', trunk='ether4', **changes):
        v=dict(id='60',name='video',subnet='10.60.0.0/24',gateway='10.60.0.1',dhcp=True,poolStart='10.60.0.10',poolEnd='10.60.0.100',tagged=trunk,untagged='ether2')
        v.update(changes)
        return generate([N(name='ether1',role='wan',pvid='1'),N(name='ether2',role='lan',pvid='60'),N(name=trunk,role='trunk',pvid='1')],[N(**v)],'1.1.1.1','ether1',model)
    def test_ax(self):
        r=self.run_case(); self.assertFalse(r['errors']); self.assertIn('dhcp-server network add',r['config']); self.assertTrue(r['config'].endswith('vlan-filtering=yes'))
    def test_rb(self):
        self.assertFalse(self.run_case('RB5009','sfp-sfpplus1')['errors'])
    def test_invalid_ip(self):
        self.assertTrue(self.run_case(gateway='999.999.999.999')['errors'])
    def test_pool(self):
        self.assertTrue(self.run_case(poolStart='10.60.0.1')['errors'])
    def test_wan_conflict(self):
        self.assertTrue(self.run_case(tagged='ether1')['errors'])
    def test_pvid(self):
        self.assertTrue(self.run_case(untagged='')['errors'])
    def test_wifi_only_vlan(self):
        v=N(id='60',name='video',subnet='10.60.0.0/24',gateway='10.60.0.1',dhcp=False,poolStart='',poolEnd='',tagged='',untagged='')
        ports=[N(name='ether1',role='wan',pvid='1')]
        self.assertTrue(generate(ports,[v],'1.1.1.1','ether1','hAP ax²')['errors'])
        r=generate(ports,[v],'1.1.1.1','ether1','hAP ax²',[60])
        self.assertFalse(r['errors']);self.assertIn('vlan-ids=60 tagged=bridge-lan',r['config'])
    def test_hybrid(self):
        ports=[N(name='ether1',role='wan',pvid='1'),N(name='ether2',role='hybrid',pvid='60')]
        def vlan(i,tagged='',untagged=''):
            return N(id=str(i),name='test',subnet=f'10.{i}.0.0/24',gateway=f'10.{i}.0.1',dhcp=True,poolStart=f'10.{i}.0.10',poolEnd=f'10.{i}.0.100',tagged=tagged,untagged=untagged)
        a,b=vlan(60,untagged='ether2'),vlan(120,tagged='ether2')
        r=generate(ports,[a,b],'1.1.1.1','ether1','hAP ax²',(),True,[120]);self.assertFalse(r['errors']);self.assertIn('pvid=60 ingress-filtering=yes frame-types=admit-all',r['config']);self.assertIn('vlan-ids=60 tagged=bridge-lan untagged=ether2',r['config']);self.assertIn('gateway=10.60.0.1 dns-server=10.60.0.1',r['config']);self.assertIn('gateway=10.120.0.1 dns-server=1.1.1.1',r['config'])
        self.assertTrue(generate(ports,[a],'1.1.1.1','ether1','hAP ax²')['errors'])
        a.tagged='ether2';self.assertTrue(generate(ports,[a,b],'1.1.1.1','ether1','hAP ax²')['errors'])
if __name__ == '__main__': unittest.main()
