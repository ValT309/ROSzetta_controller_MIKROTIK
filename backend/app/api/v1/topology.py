from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ...core.db import get_db
from ...core.security import decrypt_secret
from ...models.device import Device
from ...models.user import User
from ...services.routeros.client import RouterOSCredentials, routeros_session, _normalize_link_rate, parse_uptime
from ...services.routeros.topology_graph import build_edges, unmanaged_lldp
from ..deps import get_current_user
from threading import Lock

router = APIRouter()
_scan_lock = Lock()


def _collect(creds, err, use_fdb):
    out = dict(macs=[], neighbors=[], ports={}, logical={}, fdb=[], warnings=[], error=err, sampled_at_ms=None, uptime=None)
    if creds is None: return out
    try:
        with routeros_session(creds) as api:
            rows=list(api.path('interface'))
            out['sampled_at_ms']=time.time_ns()//1_000_000
            for r in rows:
                if r.get('mac-address'): out['macs'].append(str(r['mac-address']))
                if r.get('type')!='ether' or not r.get('name'):
                    if r.get('name'): out['logical'][str(r['name'])]=str(r.get('type') or '')
                    continue
                def counter(k):
                    try:
                        n=int(r[k]); return str(n) if n>=0 else None
                    except (KeyError,TypeError,ValueError): return None
                out['ports'][str(r['name'])]=dict(rx=counter('rx-byte'),tx=counter('tx-byte'),running=(str(r.get('running')).lower()=='true') if str(r.get('running')).lower() in {'true','false'} else None,speed=None)
            try:
                out['uptime']=parse_uptime(str(next(iter(api.path('system','resource')),{}).get('uptime') or ''))
            except Exception: out['warnings'].append('Не получен uptime')
            for r in api.path('ip','neighbor'):
                out['neighbors'].append(dict(interface=r.get('interface'),mac=r.get('mac-address'),address=r.get('address4') or r.get('address'),identity=r.get('identity'),remote_port=r.get('interface-name'),protocol=r.get('discovered-by')))
            try:
                eth=list(api.path('interface','ethernet'))
                for r in eth:
                    if r.get('name') in out['ports']:
                        p=out['ports'][str(r['name'])]
                        p.update(default_name=r.get('default-name'),mac=r.get('mac-address'),comment=r.get('comment'))
                        if r.get('mac-address'): out['macs'].append(str(r['mac-address']))
                ids=[str(r['.id']) for r in eth if r.get('.id') and r.get('name') in out['ports'] and out['ports'][r['name']]['running']]
                if ids:
                    for r in api(cmd='/interface/ethernet/monitor',numbers=','.join(ids),once=''):
                        if r.get('name') in out['ports'] and str(r.get('status')).lower() not in {'no-link','disabled'}:
                            out['ports'][r['name']]['speed']=_normalize_link_rate(r.get('rate'))
            except Exception: out['warnings'].append('Скорость линков недоступна')
            if use_fdb:
                try:
                    # Drain the API reply, but bound retained records and expose truncation.
                    for r in api.path('interface','bridge','host'):
                        if str(r.get('local')).lower()=='true' or str(r.get('dynamic')).lower()!='true': continue
                        if len(out['fdb'])>=10000:
                            if 'MAC-таблица ограничена 10000 записями' not in out['warnings']: out['warnings'].append('MAC-таблица ограничена 10000 записями')
                            continue
                        out['fdb'].append(dict(mac=r.get('mac-address'),port=r.get('on-interface') or r.get('interface')))
                except Exception: out['warnings'].append('MAC-таблица недоступна')
    except Exception:
        out['error']='Не удалось завершить опрос соседей / интерфейсов'
    return out


@router.get('')
def get_topology(group: str | None=None, fdb: bool=False, db: Session=Depends(get_db), _: User=Depends(get_current_user)) -> dict[str, Any]:
    if not _scan_lock.acquire(blocking=False):
        raise HTTPException(409, 'Опрос топологии уже выполняется; дождитесь завершения')
    try:
        devices=db.query(Device).order_by(Device.id).all()
        if group=='__none__': devices=[d for d in devices if not (d.group_name or '').strip()]
        elif group: devices=[d for d in devices if (d.group_name or '').strip()==group.strip()]
        jobs=[]; nodes=[]
        for d in devices:
            nodes.append(dict(id=f'd{d.id}',kind=d.kind,device_id=d.id,label=d.identity or d.name,name=d.name,model=d.model,host=d.host,status=d.status,group=d.group_name,location=d.location,purpose=d.purpose,comment=d.comment,inventory_number=d.inventory_number))
            if d.status=='down': jobs.append((None,'Устройство недоступно (DOWN)',fdb)); continue
            if d.use_tls and not getattr(d,'tls_fingerprint',None): jobs.append((None,'TLS без закреплённого отпечатка',fdb)); continue
            try:
                creds=RouterOSCredentials(host=d.host,username=d.username,password=decrypt_secret(d.password_enc),port=d.port,use_tls=d.use_tls,tls_fingerprint=getattr(d,'tls_fingerprint',None),timeout=8.0)
                jobs.append((creds,None,fdb))
            except Exception: jobs.append((None,'Учётные данные недоступны (проверьте Vault)',fdb))
        with ThreadPoolExecutor(max_workers=8) as pool:
            collected=list(pool.map(lambda job:_collect(*job),jobs))
        samples={n['id']:c for n,c in zip(nodes,collected)}
        edges=build_edges(nodes,samples,fdb)
        for n,c in zip(nodes,collected):
            n.update(error=c['error'],warnings=c['warnings'])
        # Only the ports belonging to returned edges are sent to the browser.
        port_samples={}
        for e in edges:
            for side in ('a','b'):
                node=e[side]; p=e[side+'_port']; c=samples[node]
                if p and p in c['ports']:
                    port_samples.setdefault(node,{})[p]=dict(c['ports'][p],sampled_at_ms=c['sampled_at_ms'],uptime=c['uptime'])
        return dict(nodes=nodes,edges=edges,unmanaged=unmanaged_lldp(nodes,samples),port_samples=port_samples,collected_at=datetime.now(timezone.utc).isoformat())
    finally:
        _scan_lock.release()
