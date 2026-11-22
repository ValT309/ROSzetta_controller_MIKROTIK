import unittest
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from hashlib import sha256
from app.services.object_plan import check_pair

class BackupPairTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime.now(timezone.utc)
        self.export=self.row(1,'text','lab.rsc',b'# export\n/ip address\nadd address=10.0.0.1/24\n')
        self.binary=self.row(2,'binary','lab.backup',b'backup-data')
    def row(self,id,fmt,filename,content):
        return SimpleNamespace(id=id,device_id=3,fmt=fmt,filename=filename,content=content,size=len(content),created_at=self.now)
    def check(self,rows): return check_pair(rows,1,self.now)
    def test_valid(self):
        r=self.check([self.export,self.binary]);self.assertTrue(r['ok']);self.assertTrue(r['fresh']);self.assertEqual(r['files'][1]['sha256'],sha256(self.binary.content).hexdigest())
    def test_missing(self): self.assertFalse(self.check([self.export])['ok'])
    def test_wrong_device(self):
        self.binary.device_id=4;self.assertFalse(self.check([self.export,self.binary])['ok'])
    def test_size_mismatch(self):
        self.binary.size+=1;self.assertFalse(self.check([self.export,self.binary])['ok'])
    def test_empty(self):
        self.binary.content=b'';self.binary.size=0;self.assertFalse(self.check([self.export,self.binary])['ok'])
    def test_stale(self):
        self.export.created_at-=timedelta(hours=1);r=self.check([self.export,self.binary]);self.assertTrue(r['ok']);self.assertFalse(r['fresh'])
    def test_ambiguous(self):
        self.assertFalse(self.check([self.export,self.binary,self.row(3,'binary','lab.backup',b'other')])['ok'])
    def test_not_text_export(self):
        self.export.content=b'\x00not text';self.export.size=len(self.export.content);self.assertFalse(self.check([self.export,self.binary])['ok'])
    def test_bad_export_id(self): self.assertFalse(check_pair([self.export,self.binary],9,self.now)['ok'])
    def test_naive_timestamp(self):
        self.export.created_at=self.now.replace(tzinfo=None);self.assertTrue(self.check([self.export,self.binary])['fresh'])

    def test_duplicate_export(self):
        self.assertFalse(self.check([self.export,self.binary,self.row(4,'text','lab.rsc',self.export.content)])['ok'])
