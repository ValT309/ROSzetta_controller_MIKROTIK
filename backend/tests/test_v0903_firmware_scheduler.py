from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import pytest
from app.services import firmware_scheduler as f


def backup_record(id, name, fmt, size=4, device=1):
    return SimpleNamespace(id=id,filename=name,fmt=fmt,size=size,content=b'test',device_id=device)

@pytest.mark.parametrize('value,expected',[('7.24.6 (long-term)','7.24.6'),('7.25.1','7.25.1'),('7.26beta1',None),('6.49.19',None)])
def test_release(value,expected):
    assert f.release(value)==expected

@pytest.mark.parametrize('value,expected',[('1w2d3h4m5s',788645),('01:02:03',3723),('x',None)])
def test_uptime(value,expected):
    assert f.uptime_seconds(value)==expected

def test_pair():
    assert f.fresh_pair([backup_record(1,'a.backup','binary'),backup_record(2,'a.rsc','text')],set(),1)==[1,2]

@pytest.mark.parametrize('old,second',[(set(),backup_record(2,'b.rsc','text')),({1},backup_record(2,'a.rsc','text')),(set(),backup_record(2,'a.rsc','text',0)),(set(),backup_record(2,'a.rsc','text',device=2))])
def test_pair_reject(old,second):
    with pytest.raises(f.FirmwareBlocked):
        f.fresh_pair([backup_record(1,'a.backup','binary'),second],old,1)


def test_time_gate():
    now=datetime(2026,11,20,18,tzinfo=timezone.utc)
    start,end=f.timing(now+timedelta(minutes=1),now,15)
    entry=dict(firmware_confirmed=True,expected_version='7.25.1',scheduled_at=start.isoformat(),deadline=end.isoformat())
    f.approved(entry,start)
    for invalid,at in [(entry,now),(entry,end),({**entry,'firmware_confirmed':False},start),({**entry,'expected_version':'7.25beta1'},start)]:
        with pytest.raises(f.FirmwareBlocked): f.approved(invalid,at)
    with pytest.raises(f.FirmwareBlocked): f.timing(now,now,15)


def test_endpoint_pin_and_identity():
    d=SimpleNamespace(host='10.0.0.1',port=8729,use_tls=True,tls_fingerprint='a'*64,identity='test',serial='123')
    e={'endpoint':f.endpoint(d)};f.verify_endpoint(d,e)
    d.port=8728
    with pytest.raises(f.FirmwareBlocked):f.verify_endpoint(d,e)
    d.port=8729;d.tls_fingerprint=None
    with pytest.raises(f.FirmwareBlocked):f.verify_endpoint(d,{'endpoint':f.endpoint(d)})


class Fake:
    def __init__(self):
        self.version='7.24.6';self.latest='7.25.1';self.channel='stable';self.up=1000;self.arch='arm64';self.name='test';self.serial='123';self.packages=['routeros','wifi-qcom'];self.files=[];self.calls=[];self.elapsed=0;self.install_effect='success';self.flags={'status':'ok','flagged':False};self.backup_result=[11,12];self.entry={'expected_version':'7.25.1','endpoint':{'identity':'test','serial':'123'}};self.validations=0
    @contextmanager
    def connect(self):
        if self.install_effect=='offline' and '/system/package/update/install' in self.calls:
            raise ConnectionError()
        yield self
    def path(self,*names):
        if names==('system','resource'): return [{'version':self.version,'uptime':str(self.up)+'s','architecture-name':self.arch,'free-hdd-space':10000000}]
        if names==('system','identity'): return [{'name':self.name}]
        if names==('system','routerboard'): return [{'serial-number':self.serial}]
        if names==('system','package'): return [{'name':n,'disabled':False,'version':self.version} for n in self.packages]
        if names==('system','package','update'): return [{'channel':self.channel,'installed-version':self.version,'latest-version':self.latest,'status':'New version is available'}]
        if names==('file',):return [{'name':n} for n in self.files]
        raise AssertionError(names)
    def __call__(self,cmd):
        self.calls.append(cmd)
        if cmd.endswith('/install'):
            if self.install_effect in ('success','disconnect','missing_package','wrong_version'):
                self.version='7.26.1' if self.install_effect=='wrong_version' else self.latest;self.up=0
                if self.install_effect=='missing_package':self.packages=['routeros']
            if self.install_effect in ('disconnect','offline'):raise ConnectionError()
        return []
    def clock(self): return self.elapsed
    def sleep(self,n):self.elapsed+=n;self.up+=int(n)
    def backup(self):
        self.calls.append('backup')
        if isinstance(self.backup_result,Exception): raise self.backup_result
        return self.backup_result
    def publish(self,detail):self.calls.append(('publish',detail))
    def validate(self):self.validations+=1
    def run(self):return f.run_update(entry=self.entry,channel='stable',connect=self.connect,guard=lambda api:self.flags,backup=self.backup,publish=self.publish,validate=self.validate,clock=self.clock,sleep=self.sleep)

@pytest.mark.parametrize('effect',['success','disconnect'])
def test_actual_update(effect):
    x=Fake();x.install_effect=effect
    assert 'Подтверждено' in x.run()
    assert x.entry['backup_ids']==[11,12]
    assert x.calls.count('/system/package/update/install')==1
    assert x.calls.index('backup')<x.calls.index('/system/package/update/install')
    assert x.calls.count('/system/package/update/check-for-updates')==2

@pytest.mark.parametrize('effect',['offline','missing_package','wrong_version'])
def test_uncertain_no_replay(effect):
    x=Fake();x.install_effect=effect
    with pytest.raises(f.FirmwareUnconfirmed):x.run()
    assert x.calls.count('/system/package/update/install')==1
    assert x.entry['install_intent'] is True

@pytest.mark.parametrize('attr,value',[('latest','7.25.2'),('channel','long-term'),('files',['routeros-7.25.1-arm64.npk']),('backup_result',f.FirmwareBlocked('failed')),('name','wrong'),('flags',{'status':'unknown'})])
def test_blocks_before_install(attr,value):
    x=Fake();setattr(x,attr,value)
    with pytest.raises(f.FirmwareBlocked):x.run()
    assert '/system/package/update/install' not in x.calls


def test_current_skips_backup_and_install():
    x=Fake();x.version=x.latest
    assert 'Уже установлена' in x.run()
    assert 'backup' not in x.calls and '/system/package/update/install' not in x.calls


def test_latest_changes_after_backup():
    x=Fake();old=x.backup
    def changed():
        result=old();x.latest='7.25.2';return result
    x.backup=changed
    with pytest.raises(f.FirmwareBlocked):x.run()
    assert '/system/package/update/install' not in x.calls


def test_stopped_at_write_intent():
    x=Fake();old=x.publish
    def stopped(detail):
        if detail.startswith('Отправка команды'):raise f.FirmwareBlocked('stopped')
        old(detail)
    x.publish=stopped
    with pytest.raises(f.FirmwareBlocked):x.run()
    assert not x.entry.get('install_intent') and '/system/package/update/install' not in x.calls
