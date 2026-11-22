"""Local fake RouterOS and SQLite tests for group management; no network."""
import unittest
from unittest.mock import patch
from fastapi import HTTPException
import test_management_jobs as old
m=old.m

class Path:
    def __init__(self,api,path): self.api=api;self.path=path
    def __iter__(self): return iter([dict(r) for r in self.api.rows.get(self.path,[])])
    def add(self,**values):
        self.api.calls.append((self.path,'add',values))
        self.api.rows.setdefault(self.path,[]).append({'.id':f'*{100+len(self.api.rows[self.path])}',**values})
    def __call__(self,cmd,**values):
        self.api.calls.append((self.path,cmd,values))
        rows=self.api.rows[self.path];row=next(r for r in rows if r.get('.id')==values['.id'])
        if cmd=='remove': rows.remove(row)
        elif cmd=='set':
            for k,v in values.items():
                if k=='.id':continue
                if k=='policy':
                    rights=set(m.effective_policies(row))
                    for policy in v.split(','):
                        if policy.startswith('!'): rights.discard(policy[1:])
                        else: rights.add(policy)
                    row[k]=','.join(sorted(rights))
                else: row[k]=v
        else: raise RuntimeError('unexpected command')
        return []

class API(old.FakeAPI):
    def __init__(self):
        super().__init__();self.rows[('user','group')].extend([
          {'.id':'*21','name':'support','policy':'read,ssh,!ftp'},
          {'.id':'*22','name':'monitor','policy':'read,api'},
          {'.id':'*23','name':'empty','policy':'read,api'},
          {'.id':'*24','name':'full','policy':'read,api,policy,write,ssh'}])
        self.rows[('user',)].extend([{'.id':'*11','name':'alice','group':'support'},{'.id':'*12','name':'admin','group':'full'}])
        self.rows[('user','aaa')][0]['default-group']='read'
    def path(self,*p):return Path(self,p)

class GroupOperations(unittest.TestCase):
    def setUp(self):self.api=API()
    def spec(self,name='new_group',rights=('read','api'),mode='create',username=''):return m.group_spec(name,rights,mode,username)
    def preview(self,**kw):return m.group_plan(self.api,'roszetta',self.spec(**kw))
    def apply(self,p):return m.apply_group_plan(self.api,'roszetta',p)
    def test_create_preview_is_readonly(self):
        p=self.preview();self.assertTrue(p['eligible']);self.assertFalse(self.api.calls);self.apply(p);self.assertEqual(m.effective_policies(m.one_named(self.api.rows[('user','group')],'new_group')),['api','read'])
    def test_duplicate_is_noop(self):
        p=self.preview(name='monitor');self.assertFalse(p['eligible']);self.assertFalse(p['attention']);self.assertFalse(self.api.calls)
    def test_collision_never_overwrites(self):
        p=self.preview(name='support');self.assertFalse(p['eligible']);self.assertTrue(p['attention']);self.assertFalse(self.api.calls)
    def test_idempotent_create_after_preview(self):
        p=self.preview();self.apply(p);self.apply(p);self.assertEqual(len(self.api.calls),1)
    def test_create_collision_after_preview(self):
        p=self.preview();self.api.rows[('user','group')].append({'.id':'*90','name':'new_group','policy':'read,ssh'});
        with self.assertRaises(m.Blocked):self.apply(p)
        self.assertFalse(self.api.calls)
    def test_add_preserves_existing_policies(self):
        p=self.preview(name='support',rights=('ftp',),mode='add');self.apply(p);self.assertEqual(self.api.calls[0][2]['policy'],'ftp');self.assertEqual(m.effective_policies(m.one_named(self.api.rows[('user','group')],'support')),['ftp','read','ssh'])
    def test_remove_explicit_negation(self):
        p=self.preview(name='support',rights=('api',),mode='add');self.apply(p);p=self.preview(name='support',rights=('ssh',),mode='remove');self.apply(p);self.assertEqual(self.api.calls[-1][2]['policy'],'!ssh')
    def test_replace_uses_explicit_delta(self):
        p=self.preview(name='support',rights=('read','api'),mode='replace');self.apply(p);self.assertEqual(self.api.calls[0][2]['policy'],'api,!ssh')
    def test_cannot_remove_all_login_of_used_group(self):
        with self.assertRaises(m.Blocked):self.preview(name='support',rights=('ssh',),mode='remove')
    def test_membership_change_detected(self):
        p=self.preview(name='support',rights=('ftp',),mode='add');self.api.rows[('user',)].append({'.id':'*45','name':'bob','group':'support'});
        with self.assertRaises(m.Blocked):self.apply(p)
        self.assertFalse(self.api.calls)
    def test_policy_change_detected(self):
        p=self.preview(name='support',rights=('ftp',),mode='add');m.one_named(self.api.rows[('user','group')],'support')['policy']='read,ssh,api';
        with self.assertRaises(m.Blocked):self.apply(p)
        self.assertFalse(self.api.calls)
    def test_controller_group_protected(self):
        with self.assertRaises(m.Blocked):self.preview(name='roszetta',rights=('ssh',),mode='remove')
    def test_system_group_rejected(self):
        for name in ('read','write','full','FULL'):
            with self.assertRaises(HTTPException):self.spec(name=name)
    def test_unknown_policy_rejected(self):
        with self.assertRaises(HTTPException):self.spec(rights=('random',))
    def test_radius_blocks_writes(self):
        self.api.rows[('user','aaa')][0]['use-radius']=True
        with self.assertRaises(m.Blocked):self.preview()
        self.assertFalse(self.api.calls)
    def test_missing_policy_right_blocks(self):
        m.one_named(self.api.rows[('user','group')],'roszetta')['policy']='read,write,api'
        with self.assertRaises(m.Blocked):self.preview()
    def test_delete_empty(self):
        p=self.preview(name='empty',mode='delete');self.apply(p);self.assertIsNone(m.one_named(self.api.rows[('user','group')],'empty'))
    def test_delete_used_blocks(self):
        with self.assertRaises(m.Blocked):self.preview(name='support',mode='delete')
    def test_delete_group_used_after_preview_blocks(self):
        p=self.preview(name='empty',mode='delete');self.api.rows[('user',)].append({'.id':'*45','name':'bob','group':'empty'});
        with self.assertRaises(m.Blocked):self.apply(p)
        self.assertFalse(self.api.calls)
    def test_aaa_default_protected(self):
        self.api.rows[('user','aaa')][0]['default-group']='empty'
        with self.assertRaises(m.Blocked):self.preview(name='empty',mode='delete')
    def test_move_user(self):
        p=self.preview(name='monitor',mode='move',username='alice');self.apply(p);self.assertEqual(m.one_named(self.api.rows[('user',)],'alice')['group'],'monitor')
    def test_admin_and_controller_cannot_move(self):
        for username in ('admin','roszetta'):
            with self.assertRaises(m.Blocked):self.preview(name='monitor',mode='move',username=username)
    def test_current_group_cannot_be_destination(self):
        with self.assertRaises(m.Blocked):self.preview(name='roszetta',mode='move',username='alice')
    def test_unconfirmed_readback_never_success(self):
        p=self.preview()
        with patch.object(Path,'add',return_value=None),self.assertRaises(m.Unconfirmed):self.apply(p)
    def test_inventory(self):
        g={x['name']:x for x in m.group_inventory(self.api,'roszetta')};self.assertTrue(g['roszetta']['protected']);self.assertTrue(g['full']['protected']);self.assertEqual(g['support']['members'],['alice']);self.assertFalse(self.api.calls)

class QueueAndTemplates(unittest.TestCase):
    def setUp(self):self.fixture=old.Queue();self.fixture.setUp();m.GroupTemplate.__table__.create(self.fixture.engine)
    def tearDown(self):self.fixture.tearDown()
    def test_preview_bound_to_server_spec(self):
        f=self.fixture;p=f.create('group-preview',ids=[1],group_name='new_group',group_policies=['read','api']);plan=m.group_plan(API(),'roszetta',p['entries'][0]['expected'])
        with patch.object(m,'execute',return_value=plan):m.tick()
        with self.assertRaises(HTTPException):f.create('group-apply',ids=[1],preview_job=p['id'])
        j=f.create('group-apply',ids=[1],preview_job=p['id'],confirmed=True,group_name='different',group_policies=['policy']);self.assertEqual(j['entries'][0]['expected']['spec']['name'],'new_group');self.assertEqual(j['entries'][0]['expected']['spec']['policies'],['api','read'])
        with self.assertRaises(HTTPException):f.create('group-apply',ids=[2],preview_job=p['id'],confirmed=True)
    def test_inventory_readonly_job(self):
        j=self.fixture.create('group-list',ids=[1]);self.assertEqual(j['action'],'group-list')
    def test_template_round_trip(self):
        f=self.fixture;b=m.GroupTemplateRequest(name='Тест',group_name='support_new',policies=['read','api']);t=m.save_group_template(b,f.db,f.user);self.assertEqual(m.list_group_templates(f.db,f.user),[t]);
        with self.assertRaises(HTTPException):m.save_group_template(b,f.db,f.user)
        b.replace=True;b.policies=['read','ssh'];t2=m.save_group_template(b,f.db,f.user);self.assertEqual(t2['id'],t['id']);self.assertEqual(t2['policies'],['read','ssh']);m.delete_group_template(t['id'],f.db,f.user);self.assertEqual(m.list_group_templates(f.db,f.user),[])

if __name__=='__main__':unittest.main(verbosity=2)
