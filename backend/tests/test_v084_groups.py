import unittest
from test_v093_groups import API,m
class AdditiveGroups(unittest.TestCase):
    def setUp(self): self.api=API()
    def plan(self, name='roszetta', mode='add', rights=('ssh',)):
        return m.group_plan(self.api,'roszetta',m.group_spec(name,rights,mode))
    def apply(self,p): return m.apply_group_plan(self.api,'roszetta',p)
    def test_controller_add_only(self):
        p=self.plan(); self.assertTrue(p['eligible']); self.assertFalse(self.api.calls); self.apply(p)
        self.assertEqual(self.api.calls[0][2]['policy'],'ssh'); self.assertEqual(set(p['group_before']['policies'])|{'ssh'},set(p['group_after']))
    def test_controller_noop(self):
        p=self.plan(rights=('api',));self.assertFalse(p['eligible']);self.assertFalse(p['attention']);self.assertFalse(self.api.calls)
    def test_controller_protection(self):
        for mode in ('replace','delete','remove'):
            with self.assertRaises(m.Blocked):self.plan(mode=mode)
    def test_upsert_existing(self):
        p=self.plan(mode='upsert');self.apply(p);self.assertEqual(self.api.calls[0][1],'set')
    def test_upsert_missing(self):
        p=self.plan('new_group','upsert',('read','api'));self.apply(p);self.assertEqual(self.api.calls[0][1],'add')
    def test_upsert_existing_noop(self):
        p=self.plan('monitor','upsert',('read',)); self.assertFalse(p['eligible']);self.assertFalse(p['attention'])
    def test_upsert_race(self):
        p=self.plan('new_group','upsert',('read','api'));self.api.rows[('user','group')].append({'.id':'*99','name':'new_group','policy':'read'})
        with self.assertRaises(m.Blocked): self.apply(p)
        self.assertFalse(self.api.calls)
    def test_aaa_blocks_add(self):
        self.api.rows[('user','aaa')][0]['default-group']='roszetta'
        with self.assertRaises(m.Blocked):self.plan()
    def test_radius_blocks_upsert(self):
        self.api.rows[('user','aaa')][0]['use-radius']=True
        with self.assertRaises(m.Blocked):self.plan(mode='upsert')
    def test_member_race(self):
        p=self.plan();self.api.rows[('user',)].append({'name':'new_user','group':'roszetta'})
        with self.assertRaises(m.Blocked):self.apply(p)
        self.assertFalse(self.api.calls)
