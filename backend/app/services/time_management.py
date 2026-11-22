"""Read RouterOS wall clock in UTC; additive NTP configuration only."""
import ipaddress
import re
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

class TimeBlocked(ValueError): pass
class TimeUnconfirmed(ValueError): pass

def truth(v): return str(v).lower() in ('true','yes','1')

def parse_clock(row):
    date=str(row.get('date','')); clock=str(row.get('time','')); offset=str(row.get('gmt-offset',''))
    m=re.fullmatch(r'([+-])(\d{2}):(\d{2})(?::(\d{2}))?',offset)
    if m:
        secs=(int(m[2])*3600+int(m[3])*60+int(m[4] or 0))*(-1 if m[1]=='-' else 1)
    elif re.fullmatch(r'[+-]?\d+',offset): secs=int(offset)
    else: raise ValueError('GMT offset unavailable')
    for fmt in ('%Y-%m-%d','%b/%d/%Y'):
        try: return datetime.strptime(date+' '+clock,fmt+' %H:%M:%S').replace(tzinfo=timezone(timedelta(seconds=secs))).astimezone(timezone.utc)
        except ValueError: pass
    raise ValueError('Clock format unavailable')

def clock_check(api, now=None):
    try:
        rows=list(api.path('system','clock'))
        if len(rows)!=1: raise ValueError()
        clock=rows[0]; actual=parse_clock(clock)
    except Exception as exc: raise TimeBlocked('Не удалось прочитать дату, время и GMT MikroTik') from exc
    now=now or datetime.now(timezone.utc)
    delta=round((actual-now).total_seconds())
    return dict(device_time=actual.isoformat(), controller_time=now.isoformat(), offset_seconds=delta, timezone=str(clock.get('time-zone-name','')), clock_ok=abs(delta)<=300)

def format_offset(seconds):
    days,rem=divmod(abs(seconds),86400); hours,rem=divmod(rem,3600); minutes,secs=divmod(rem,60)
    parts=[f"{v} {unit}" for v,unit in ((days,"дн."),(hours,"ч"),(minutes,"мин"),(secs,"с")) if v]
    return ("−" if seconds<0 else "+" if seconds>0 else "")+(" ".join(parts) or "0 с")

def inspect(api):
    r=clock_check(api)
    try:
        rows=list(api.path('system','ntp','client'))
        if len(rows)!=1: raise ValueError()
        client=rows[0]; servers=list(api.path('system','ntp','client','servers'))
        r.update(ntp_enabled=truth(client.get('enabled')),ntp_status=str(client.get('status') or 'unknown'),servers=[str(s.get('address','')) for s in servers if s.get('address')])
    except Exception: r.update(ntp_enabled=None,ntp_status='unknown',servers=[])
    r['attention']=not r['clock_ok'] or not r['ntp_enabled'] or r['ntp_status']!='synchronized'
    r['detail']=f"Время UTC: {r['device_time']}; расхождение {format_offset(r['offset_seconds'])}; зона {r['timezone']}; NTP: {r['ntp_status']}; серверы: {', '.join(r['servers']) or '—'}"+(' — исправьте время до выпуска TLS' if not r['clock_ok'] else '')
    return r

def validate(servers, zone):
    if not 1<=len(servers)<=4: raise TimeBlocked('Укажите от 1 до 4 NTP-серверов')
    result=[]
    for raw in servers:
        s=raw.strip().lower()
        try: s=str(ipaddress.ip_address(s))
        except ValueError:
            if len(s)>253 or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',s): raise TimeBlocked('Недопустимый адрес NTP-сервера')
        if s not in result: result.append(s)
    if zone:
        try: ZoneInfo(zone)
        except Exception as exc: raise TimeBlocked('Недопустимый часовой пояс') from exc
    return dict(servers=result,zone=zone)

def configure(api,spec):
    before=inspect(api)
    if before['ntp_enabled'] is None: raise TimeBlocked('Состояние NTP не подтверждено; настройки не изменены')
    rows=list(api.path('system','ntp','client','servers'))
    # Never overwrite DHCP-learned servers or existing entries. Disabled matching entries require review.
    for s in spec['servers']:
        if any(str(r.get('address','')).lower()==s and truth(r.get('disabled')) for r in rows): raise TimeBlocked('Найден отключённый NTP-сервер; включите его вручную')
    try:
        for s in spec['servers']:
            if not any(str(r.get('address','')).lower()==s for r in rows): list(api(cmd='/system/ntp/client/servers/add',address=s))
        if not before['ntp_enabled']: list(api(cmd='/system/ntp/client/set',enabled='yes'))
        if spec['zone']: list(api(cmd='/system/clock/set',**{'time-zone-name':spec['zone'],'time-zone-autodetect':'no'}))
        after=inspect(api)
        if not after['ntp_enabled'] or not set(spec['servers'])<=set(s.lower() for s in after['servers']) or (spec['zone'] and after['timezone']!=spec['zone']): raise ValueError()
    except Exception as exc: raise TimeUnconfirmed('Настройки NTP могли измениться; повторите аудит, не запись') from exc
    after['detail']='Настройки NTP проверены; '+after['detail']+'; прежние серверы сохранены. Повторите аудит после синхронизации.'
    return after

def require_clock(api):
    r=clock_check(api)
    if not r['clock_ok']: raise TimeBlocked(f"Время MikroTik отличается от контроллера на {format_offset(r['offset_seconds'])}; настройте NTP перед выпуском TLS")
    return r
