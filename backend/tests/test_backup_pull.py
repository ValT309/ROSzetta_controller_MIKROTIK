import importlib.util, sys, types, unittest, io, tempfile
from pathlib import Path
from unittest.mock import patch, Mock
from contextlib import contextmanager
root=Path(__file__).resolve().parents[1]/'app/services/routeros'
pkg=types.ModuleType('pull_test');pkg.__path__=[];sys.modules[pkg.__name__]=pkg
client=types.ModuleType('pull_test.client');client.RouterOSError=RuntimeError;client.routeros_session=None;sys.modules[client.__name__]=client

def load(name):
    spec=importlib.util.spec_from_file_location('pull_test.'+name,root/(name+'.py'));m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
try:
    import paramiko
except ImportError:
    stub=types.ModuleType('paramiko');stub.SSHClient=Mock();stub.RejectPolicy=Mock();sys.modules['paramiko']=stub
m=load('backup_pull'); load('management'); audit=load('security_audit')
class Tests(unittest.TestCase):
    def test_exact(self):
        s=Mock();s.open.return_value=io.BytesIO(b'abc');self.assertEqual(m.download_exact(s,'x',3),b'abc');s.open.assert_called_once_with('x','rb')
    def test_short(self):
        s=Mock();s.open.return_value=io.BytesIO(b'a');self.assertRaisesRegex(RuntimeError,'mismatch',m.download_exact,s,'x',3)
    def test_long(self):
        s=Mock();s.open.return_value=io.BytesIO(b'abcd');self.assertRaisesRegex(RuntimeError,'mismatch',m.download_exact,s,'x',3)
    def test_size(self):
        s=Mock()
        for n in (0,-1,m.MAX_FILE+1):self.assertRaisesRegex(RuntimeError,'size',m.download_exact,s,'x',n)
        s.open.assert_not_called()
    def test_audit(self):
        @contextmanager
        def session(c):
            api=Mock();api.path.side_effect=lambda *p: [{'name':'ssh','port':22,'password':'secret'}] if p==('ip','service') else []
            yield api
        with patch.object(audit,'routeros_session',session):r=audit.inspect_security(None)
        self.assertEqual(r['services']['rows'][0]['port'],22);self.assertNotIn('password',r['services']['rows'][0]);self.assertEqual(r['dns']['status'],'unknown')
    def test_audit_partial_failure(self):
        @contextmanager
        def session(c):
            api=Mock();api.path.side_effect=RuntimeError('secret');yield api
        with patch.object(audit,'routeros_session',session):r=audit.inspect_security(None)
        self.assertTrue(all(v=={'status':'unknown','rows':[]} for v in r.values()))
    def test_missing_key(self):
        b=types.ModuleType('pull_test.backup')
        for k in ('BackupFiles','_exec_path','_wait_file','_delete_file','_list_files'):setattr(b,k,Mock())
        with tempfile.TemporaryDirectory() as d, patch.dict(sys.modules,{'pull_test.backup':b}),patch.dict(m.os.environ,{'ROSZETTA_SFTP_KNOWN_HOSTS':d+'/missing'}),patch.object(m.paramiko,'SSHClient') as ssh:
            self.assertRaisesRegex(RuntimeError,'trusted host key',m.create_backup_via_pull,Mock(),'base');ssh.assert_not_called()
if __name__=='__main__':unittest.main()
