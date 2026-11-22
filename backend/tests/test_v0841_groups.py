import unittest
from test_v093_groups import API,m

RIGHTS=('ssh','ftp','reboot','read','write','policy','test','sensitive','api')
class RealGroupRegression(unittest.TestCase):
    def setUp(self):
        self.api=API()
        self.api.rows[('user','aaa')][0].update({'use-radius':'no','accounting':'yes','default-group':'read'})
        m.one_named(self.api.rows[('user','group')],'roszetta')['policy']=','.join(RIGHTS)+',!local,!telnet,!winbox,!password,!web,!sniff,!romon,!rest-api'
    def plan(self, mode='upsert', rights=RIGHTS):
        return m.group_plan(self.api,'roszetta',m.group_spec('roszetta',rights,mode))
    def test_real_noop_create_add_upsert(self):
        for mode in ('create','add','upsert'):
            p=self.plan(mode);self.assertFalse(p['eligible']);self.assertFalse(p['attention'])
        self.assertFalse(self.api.calls)
    def test_add_existing_missing_ssh(self):
        m.one_named(self.api.rows[('user','group')],'roszetta')['policy']=','.join(x for x in RIGHTS if x!='ssh')+',!ssh'
        p=self.plan();self.assertTrue(p['eligible']);m.apply_group_plan(self.api,'roszetta',p)
        self.assertEqual(self.api.calls[0][2]['policy'],'ssh');self.assertFalse(self.plan()['eligible'])
    def test_radius_enabled(self):
        self.api.rows[('user','aaa')][0]['use-radius']='yes'
        with self.assertRaisesRegex(m.Blocked,'RADIUS включён'):self.plan()
    def test_unknown_radius_is_not_disabled(self):
        self.api.rows[('user','aaa')][0].pop('use-radius')
        with self.assertRaisesRegex(m.Blocked,'Не удалось определить'):self.plan()
    def test_protected_destructive_operations(self):
        for mode in ('remove','replace','delete'):
            with self.assertRaises(m.Blocked):self.plan(mode)
    def test_already_applied_does_not_write_again(self):
        row=m.one_named(self.api.rows[('user','group')],'roszetta');row['policy']=','.join(x for x in RIGHTS if x!='ssh')
        p=self.plan();m.apply_group_plan(self.api,'roszetta',p);m.apply_group_plan(self.api,'roszetta',p)
        self.assertEqual(len(self.api.calls),1)
    def test_membership_change_blocks_apply(self):
        row=m.one_named(self.api.rows[('user','group')],'roszetta');row['policy']=','.join(x for x in RIGHTS if x!='ssh')
        p=self.plan();self.api.rows[('user',)].append({'name':'someone','group':'roszetta'})
        with self.assertRaises(m.Blocked):m.apply_group_plan(self.api,'roszetta',p)
        self.assertFalse(self.api.calls)
