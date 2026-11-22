"""Pure topology inference. FDB is reachability evidence, never physical proof."""
import re
from collections import defaultdict


def mac(value):
    raw = str(value or '').strip()
    if not re.fullmatch(r'(?:[0-9a-fA-F]{12}|(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})', raw): return None
    s = re.sub(r'[:-]', '', raw).upper()
    return s if len(s) == 12 and s not in {'000000000000', 'FFFFFFFFFFFF'} else None


def port(value, known):
    raw = str(value or '').strip()
    if raw in known:
        return raw
    tokens = {x.strip() for x in re.split(r'[,/]', raw)}
    matches = {name for name,info in known.items() if name in tokens or (info.get('default_name') and info['default_name'] in tokens)}
    return next(iter(matches)) if len(matches) == 1 else None


def build_edges(nodes, samples, use_fdb=False):
    indexes = [defaultdict(set) for _ in range(3)]
    for n in nodes:
        a = n['id']
        for m in samples[a].get('macs', []):
            if mac(m): indexes[0][mac(m)].add(a)
        for name in (n.get('label'), n.get('name')):
            if name: indexes[1][name.strip().casefold()].add(a)
        if n.get('host'): indexes[2][str(n['host'])].add(a)

    def resolve(row):
        # Conflicting positive evidence must never be silently overridden.
        keys = (mac(row.get('mac')), str(row.get('identity') or '').strip().casefold(), str(row.get('address') or ''))
        candidates = [idx[key] for idx, key in zip(indexes, keys) if key and idx.get(key)]
        common = set.intersection(*candidates) if candidates else set()
        return next(iter(common)) if len(common) == 1 else None

    obs = {}
    physical_protocols = defaultdict(set)
    vpn_pairs = defaultdict(set)
    for a, s in samples.items():
        for n in s.get('neighbors', []):
            b = resolve(n)
            if not b or a == b: continue
            pa = port(n.get('interface'), s.get('ports', {}))
            pb = port(n.get('remote_port'), samples[b].get('ports', {}))
            k = (a, pa, b, pb)
            protocols = set(re.findall(r'\b(?:lldp|mndp|cdp)\b', str(n.get('protocol') or '').lower()))
            raw_local = str(n.get('interface') or '').strip()
            raw_remote = str(n.get('remote_port') or '').strip()
            if not pa and (raw_local.lower().lstrip('<!').startswith('l2tp') or s.get('logical',{}).get(raw_local,'').startswith('l2tp')):
                vpn_pairs[tuple(sorted((a,b)))].update(protocols)
                continue
            obs.setdefault(k, set()).update(protocols)
            def physical_context(raw, sample):
                return not any(sample.get('logical',{}).get(token.strip(),'bridge')!='bridge' for token in re.split(r'[,/]',raw))
            if pa and pb and physical_context(raw_local,s) and physical_context(raw_remote,samples[b]):
                physical_protocols[k].update(protocols)
    keys = sorted(obs, key=lambda k: tuple(v or '' for v in k))
    edges, used = [], set()

    def make(a, pa, b, pb, evidence, protocols):
        p = samples[a].get('ports', {}).get(pa, {})
        q = samples[b].get('ports', {}).get(pb, {})
        speeds = {r.get('speed') for r in (p, q) if r.get('speed')}
        running = [r.get('running') for r in (p,q) if r.get('running') is not None]
        link_state = ('down' if False in running else 'up' if len(running)==2 else 'partial' if running else 'unknown') if evidence!='fdb' else 'unknown'
        return dict(a=a,b=b,a_port=pa,b_port=pb,evidence=evidence,protocols=sorted(protocols),
                    speed=next(iter(speeds)) if len(speeds)==1 else None,
                    speed_conflict=len(speeds)>1, link_state=link_state)

    # LLDP is link-local evidence; CDP/MNDP on a shared L2 segment must not
    # compete with an LLDP candidate. Reject competing LLDP endpoints.
    candidates = set()
    for a, pa, b, pb in keys:
        k = (a, pa, b, pb)
        if pa and pb and 'lldp' in physical_protocols[k]:
            candidates.add(tuple(sorted(((a,pa),(b,pb)))))
    endpoints = defaultdict(set)
    for pair in candidates:
        for endpoint in pair: endpoints[endpoint].add(pair)
    external = {(row['device'],row['port']) for row in unmanaged_lldp(nodes,samples)}
    physical = {pair for pair in candidates if all(len(endpoints[x]) == 1 and x not in external for x in pair)}
    for pair in sorted(physical):
        (a,pa),(b,pb)=pair
        k,rev=(a,pa,b,pb),(b,pb,a,pa)
        mutual='lldp' in physical_protocols[k] and 'lldp' in physical_protocols[rev]
        edges.append(make(a,pa,b,pb,'confirmed' if mutual else 'probable',obs.get(k,set())|obs.get(rev,set())))
        used.update((k,rev))
    for k in keys:
        if k in used: continue
        a,pa,b,pb=k
        rev=(b,pb,a,pa)
        if pa and pb and rev in obs:
            edges.append(make(a,pa,b,pb,'neighbor',obs[k]|obs[rev]));used.add(rev)
        else: edges.append(make(a,pa,b,pb,'neighbor',obs[k]))
        used.add(k)
    if use_fdb:
        pairs = {frozenset((e['a'],e['b'])) for e in edges}
        candidates=defaultdict(set)
        for a,s in samples.items():
            for r in s.get('fdb',[]):
                owners=indexes[0].get(mac(r.get('mac')),set())
                p=port(r.get('port'),s.get('ports',{}))
                if len(owners)!=1 or not p: continue
                b=next(iter(owners))
                if a!=b and frozenset((a,b)) not in pairs: candidates[a,b].add(p)
        # FDB paths may be multi-hop; exclude ambiguous paths and deduplicate reverse evidence.
        for (a,b), ports in sorted(candidates.items()):
            if len(ports)!=1 or frozenset((a,b)) in pairs: continue
            reverse=candidates.get((b,a),set())
            edges.append(make(a,next(iter(ports)),b,next(iter(reverse)) if len(reverse)==1 else None,'fdb',set()))
            pairs.add(frozenset((a,b)))
    # Identical unoriented observations must not render duplicate edges.
    unique = {}
    for e in edges:
        k = tuple(sorted(((e['a'],e['a_port'] or ''),(e['b'],e['b_port'] or ''))))
        if k in unique:
            if e['evidence'] in {'confirmed','probable'} and unique[k]['evidence'] not in {'confirmed','probable'}:
                e['protocols']=sorted(set(e['protocols'])|set(unique[k]['protocols']));unique[k]=e
            unique[k]['protocols'] = sorted(set(unique[k]['protocols']) | set(e['protocols']))
        else: unique[k] = e
    result = list(unique.values())
    confirmed_pairs = {frozenset((e['a'],e['b'])) for e in result if e['evidence'] in {'confirmed','probable'}}
    logical = {}
    for e in result:
        if e['evidence']!='neighbor': continue
        pair = frozenset((e['a'],e['b']))
        if pair in confirmed_pairs: continue
        if pair not in logical: logical[pair] = []
        logical[pair].append(e)
    merged = []
    for rows in logical.values():
        a,b = sorted((rows[0]['a'],rows[0]['b']))
        ports = [set(),set()]
        for e in rows:
            for i,side in enumerate(('a','b') if e['a']==a else ('b','a')):
                if e[side+'_port']: ports[i].add(e[side+'_port'])
        e = make(a,next(iter(ports[0])) if len(ports[0])==1 else None,b,next(iter(ports[1])) if len(ports[1])==1 else None,'neighbor',set().union(*(set(r['protocols']) for r in rows)))
        e['observations'] = len(rows)
        merged.append(e)
    return [e for e in result if e['evidence']!='neighbor'] + merged + [make(a,None,b,None,'vpn',vpn_pairs[a,b]) for a,b in sorted(vpn_pairs)]


def unmanaged_lldp(nodes, samples):
    names={str(v).strip().casefold() for n in nodes for v in (n.get('label'),n.get('name')) if v}
    addresses={str(n.get('host')) for n in nodes if n.get('host')}
    macs={mac(m) for sample in samples.values() for m in sample.get('macs',[]) if mac(m)}
    result={}
    for a,s in samples.items():
        for row in s.get('neighbors',[]):
            if 'lldp' not in re.findall(r'\b(?:lldp|mndp|cdp)\b',str(row.get('protocol') or '').lower()): continue
            p=port(row.get('interface'),s.get('ports',{}))
            identity=str(row.get('identity') or '').strip()
            address=str(row.get('address') or '')
            m=mac(row.get('mac'))
            if not p or not (identity or m) or identity.casefold() in names or address in addresses or m in macs: continue
            key=(a,p,m or identity.casefold())
            result[key]=dict(device=a,port=p,identity=identity,mac=m,address=address,remote_port=row.get('remote_port'))
    return list(result.values())[:500]
