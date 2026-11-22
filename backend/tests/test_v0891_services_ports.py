"""Read-only diagnostic and additive service ACL behavior, using fake RouterOS."""
import ast
from pathlib import Path
import unittest
from typing import Any
from test_management_jobs import FakeAPI, m, SOURCE
from unittest.mock import patch
import types

class ServiceCompatibility(unittest.TestCase):
    def setUp(self):
        self.api=FakeAPI()
        self.row=self.api.rows[('ip','service')][1]
    def modern(self, address):
        self.row.pop('address',None);self.row['available-from']=address
    def test_new_field_and_dynamic_row(self):
        self.modern('10.10.0.0/16,10.70.0.0/16')
        self.api.rows[('ip','service')].append({'name':'api-ssl','dynamic':True,'available-from':'192.0.2.1'})
        self.assertEqual(m.mg.static_service(self.api,'api-ssl')['address'],'10.10.0.0/16,10.70.0.0/16')
    def test_additive_new_field(self):
        self.modern('10.10.0.0/16,10.70.0.0/16');self.row.update(disabled=False,certificate='old')
        old,new=m.mg.append_service_source(self.api,'api-ssl',SOURCE)
        self.assertEqual(old['address'],'10.10.0.0/16,10.70.0.0/16')
        self.assertEqual(new['address'],'10.10.0.0/16,10.70.0.0/16,'+SOURCE)
        self.assertEqual(self.api.calls[-1][2],{'.id':'*2','available-from':new['address']})
        self.assertEqual(self.row['certificate'],'old');self.assertFalse(self.row['disabled'])
    def test_old_field_additive_api(self):
        row=self.api.rows[('ip','service')][0];row['address']='192.0.2.1/32'
        m.mg.append_service_source(self.api,'api',SOURCE)
        self.assertEqual(row['address'],'192.0.2.1/32,'+SOURCE)
        self.assertEqual(self.api.calls[-1][2]['address'],row['address'])
    def test_covered_address_no_write(self):
        self.modern('10.110.0.0/24');m.mg.append_service_source(self.api,'api-ssl',SOURCE);self.assertFalse(self.api.calls)
    def test_unrestricted_no_write(self):
        for value in ('','0.0.0.0/0','::/0'):
            self.modern(value);m.mg.append_service_source(self.api,'api-ssl',SOURCE)
        self.assertFalse(self.api.calls)
    def test_missing_and_conflict_fail_closed(self):
        self.row.pop('address',None)
        with self.assertRaises(ValueError):m.mg.append_service_source(self.api,'api-ssl',SOURCE)
        self.row.update(address='192.0.2.1',**{'available-from':'192.0.2.2'})
        with self.assertRaises(ValueError):m.mg.append_service_source(self.api,'api-ssl',SOURCE)
        self.assertFalse(self.api.calls)
    def test_invalid_source(self):
        self.modern('192.0.2.1')
        with self.assertRaises(ValueError):m.mg.append_service_source(self.api,'api-ssl','10.110.0.0/24')
        self.assertFalse(self.api.calls)
    def test_new_field_enabling_tls(self):
        self.modern('10.10.0.0/16');self.row['certificate']='existing'
        self.api.rows[('certificate',)]=[{'.id':'*40','name':'existing','key-usage':'tls-server','private-key':True,'fingerprint':'b'*64}]
        d=types.SimpleNamespace(host='192.0.2.1',use_tls=False,port=8728,tls_fingerprint=None)
        result=m.prepare_tls(self.api,d,SOURCE)
        self.assertEqual(result[-1]['address'],'10.10.0.0/16,'+SOURCE)
        self.assertEqual(self.api.calls[-1][2]['available-from'],result[-1]['address'])
    def test_enabled_tls_prepare_keeps_cert(self):
        self.modern('10.10.0.0/16');self.row.update(disabled=False,certificate='existing')
        self.api.rows[('certificate',)]=[{'.id':'*40','name':'existing','key-usage':'tls-server','private-key':True,'fingerprint':'b'*64}]
        d=types.SimpleNamespace(host='192.0.2.1',use_tls=False,port=8728,tls_fingerprint=None)
        m.prepare_tls(self.api,d,SOURCE)
        self.assertEqual(self.row['available-from'],'10.10.0.0/16,'+SOURCE)
        self.assertEqual(self.row['certificate'],'existing');self.assertEqual(len(self.api.calls),1)
    def test_live_tls_no_acl_write_during_prepare(self):
        self.modern('10.10.0.0/16');self.row.update(disabled=False,certificate='existing')
        self.api.rows[('certificate',)]=[{'.id':'*40','name':'existing','key-usage':'tls-server','private-key':True,'fingerprint':'b'*64}]
        d=types.SimpleNamespace(host='192.0.2.1',use_tls=True,port=8729,tls_fingerprint='b'*64)
        m.prepare_tls(self.api,d,SOURCE);self.assertFalse(self.api.calls)

# Exercise the actual diagnostic collectors with no librouteros/network dependency.
source=Path(__file__).resolve().parents[1]/'app/services/routeros/client.py'
class Logger:
    def debug(self,*a):pass
ns={'Any':Any,'logger':Logger()}
names={'_normalize_link_rate','_fetch_ethernet_link_speeds','_fetch_port_diagnostics'}
exec(compile(ast.Module(body=[n for n in ast.parse(source.read_text()).body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]),str(source),'exec'),ns)
class PortAPI:
    def __init__(self, fail=False):self.calls=[];self.fail=fail
    def path(self,*parts):
        self.calls.append(parts)
        if parts==('interface','ethernet'):return [{'name':'SFP','.id':'*1','default-name':'sfp-sfpplus1'},{'name':'LAN','.id':'*2','poe-out':'auto-on'}]
        if self.fail:raise RuntimeError('not supported')
        return [{'name':'LAN','.id':'*2','poe-out':'auto-on'}]
    def __call__(self,cmd,**args):
        self.calls.append((cmd,args))
        if self.fail:raise RuntimeError('not supported')
        if cmd=='/interface/ethernet/monitor':return [{'name':'SFP','rate':'10Gbps','status':'link-ok','sfp-temperature':'37C','sfp-rx-power':'-4.2dBm','full-duplex':True,'unrelated':'secret'}]
        if cmd=='/interface/ethernet/print':return [{'name':'LAN','rx-fcs-error':0,'rx-overflow':2}]
        if cmd=='/interface/ethernet/poe/monitor':return [{'name':'LAN','poe-out-status':'powered-on','poe-out-power':'9.5W'}]
        raise AssertionError(cmd)
class PortDiagnostics(unittest.TestCase):
    def test_optics_and_factory(self):
        names={};diag={};api=PortAPI();speeds=ns['_fetch_ethernet_link_speeds'](api,names,diag)
        self.assertEqual(speeds,{'SFP':'10G'});self.assertEqual(names['SFP'],'sfp-sfpplus1');self.assertEqual(diag['SFP']['sfp-rx-power'],'-4.2dBm');self.assertNotIn('unrelated',diag['SFP'])
    def test_poe_and_errors(self):
        api=PortAPI();diag={};ns['_fetch_port_diagnostics'](api,diag)
        self.assertEqual(diag['LAN']['rx-fcs-error'],'0');self.assertEqual(diag['LAN']['poe-out-status'],'powered-on');self.assertEqual(diag['LAN']['poe-out-power'],'9.5W')
    def test_unsupported_does_not_invent_data(self):
        diag={};ns['_fetch_port_diagnostics'](PortAPI(True),diag);self.assertEqual(diag,{})
    def test_monitor_failure_still_yields_factory_name(self):
        names={};diag={};speeds=ns['_fetch_ethernet_link_speeds'](PortAPI(True),names,diag);self.assertEqual(speeds,{});self.assertEqual(names['SFP'],'sfp-sfpplus1');self.assertNotIn('sfp-temperature',diag['SFP'])
