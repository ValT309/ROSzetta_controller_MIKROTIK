import { useEffect, useMemo, useRef, useState } from 'react';
import type { PointerEvent as ReactPointerEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { Network, RefreshCw } from 'lucide-react';
import { api, Device } from '@/api/client';
import { resolveDevicePreview } from '@/utils/devicePreview';
import { useAuth } from '@/store/auth';
import { loadGraph, emptyGraph, edgeKey, portRate, evidenceColor, evidenceLabel, parseTopologySnapshot, mergeManualEdges, changeManualEdge, removeManualEdge } from '@/utils/topologyGraph';
import type { SavedGraph, PortSample, Evidence, TopologyEdge } from '@/utils/topologyGraph';
interface TNode {id:string;kind:string;device_id:number;label:string;model:string|null;host:string;status:string;group:string|null;error:string|null;warnings?:string[];location?:string|null;purpose?:string|null;comment?:string|null;inventory_number?:string|null}
type TEdge=TopologyEdge;
interface TopoOut {unmanaged?:{device:string;port:string;identity:string;mac:string|null;address:string;remote_port:string|null}[];nodes:TNode[];edges:TEdge[];port_samples:Record<string,Record<string,PortSample>>;collected_at:string}
const NODE_W = 210;
const NODE_H = 92;
const H_GAP = 28;
const V_GAP = 100;
const PAD = 24;
const COLS = 6;

function layout(nodes: TNode[], edges: TEdge[], rootId: string | null) {
  const adj = new Map<string, Set<string>>();
  nodes.forEach((n) => adj.set(n.id, new Set()));
  edges.forEach((e) => { adj.get(e.a)?.add(e.b); adj.get(e.b)?.add(e.a); });
  const label = new Map(nodes.map((n) => [n.id, n.label]));

  // Корень: выбранный, иначе устройство с наибольшим числом связей
  const start = [...nodes].sort((x, y) => {
    const px = x.id === rootId ? 0 : 1;
    const py = y.id === rootId ? 0 : 1;
    if (px !== py) return px - py;
    const kx = x.kind === 'router' ? 0 : 1;
    const ky = y.kind === 'router' ? 0 : 1;
    if (kx !== ky) return kx - ky;
    return adj.get(y.id)!.size - adj.get(x.id)!.size;
  });

  const seen = new Set<string>();
  const comps: string[][][] = [];
  const isolated: string[] = [];
  for (const s of start) {
    if (seen.has(s.id)) continue;
    seen.add(s.id);
    if (adj.get(s.id)!.size === 0) { isolated.push(s.id); continue; }
    const levels: string[][] = [[s.id]];
    let frontier = [s.id];
    while (frontier.length) {
      const next: string[] = [];
      for (const id of frontier) {
        for (const nb of adj.get(id)!) {
          if (!seen.has(nb)) { seen.add(nb); next.push(nb); }
        }
      }
      if (next.length) levels.push(next);
      frontier = next;
    }
    for (let k = 1; k < levels.length; k++) {
      const prev = levels[k - 1];
      const score = (id: string) => {
        const idx = prev.map((p, i) => (adj.get(id)!.has(p) ? i : -1)).filter((i) => i >= 0);
        return idx.length ? idx.reduce((a, b) => a + b, 0) / idx.length : 0;
      };
      levels[k].sort(
        (a, b) => score(a) - score(b) || String(label.get(a)).localeCompare(String(label.get(b)), 'ru'),
      );
    }
    comps.push(levels);
  }

  const rowW = (c: number) => c * NODE_W + (c - 1) * H_GAP;
  let maxW = 0;
  comps.forEach((lv) => lv.forEach((l) => { maxW = Math.max(maxW, rowW(l.length)); }));
  if (isolated.length) maxW = Math.max(maxW, rowW(Math.min(COLS, isolated.length)));
  const canvasW = Math.max(maxW + PAD * 2, 640);
  const cx0 = canvasW / 2;

  const pos = new Map<string, { cx: number; y: number }>();
  const place = (ids: string[], yy: number) => {
    const total = rowW(ids.length);
    ids.forEach((id, i) =>
      pos.set(id, { cx: cx0 - total / 2 + NODE_W / 2 + i * (NODE_W + H_GAP), y: yy }),
    );
  };

  let y = PAD;
  for (const lv of comps) {
    lv.forEach((ids, k) => place(ids, y + k * (NODE_H + V_GAP)));
    y += (lv.length - 1) * (NODE_H + V_GAP) + NODE_H + V_GAP;
  }
  if (isolated.length) y += 12;
  for (let i = 0; i < isolated.length; i += COLS) {
    place(isolated.slice(i, i + COLS), y);
    y += NODE_H + 24;
  }
  return { pos, canvasW, canvasH: y + PAD };
}

const cut=(s:string,n:number)=>s.length>n?s.slice(0,n-1)+'…':s;
const bps=(n:number)=>n>=1e9?`${(n/1e9).toFixed(2)} Гбит/с`:n>=1e6?`${(n/1e6).toFixed(2)} Мбит/с`:`${(n/1e3).toFixed(1)} кбит/с`;
const read=(key:string)=>{try{return loadGraph(localStorage.getItem(key))}catch{return emptyGraph()}};
// Last successful snapshot is scoped to controller user and object, independent of the editable graph.
const readSnapshot=(key:string):TopoOut|null=>{try{return parseTopologySnapshot<TopoOut>(localStorage.getItem(key+':snapshot'))}catch{return null}};
const readScope=(key:string)=>{try{return localStorage.getItem(key+':scope')}catch{return null}};
const memorySnapshots=new Map<string,TopoOut>();
const readView=(key:string)=>{try{return JSON.parse(localStorage.getItem(key+':view')||'{}')||{}}catch{return {}}};

export default function TopologyPanel(){
 const navigate=useNavigate(),email=useAuth(s=>s.email);
 const [groups,setGroups]=useState<string[]>([]),[group,setGroup]=useState<string|null>(null),[ungrouped,setUngrouped]=useState(false);
 const [data,setData]=useState<TopoOut|null>(null),[previous,setPrevious]=useState<TopoOut|null>(null),[loading,setLoading]=useState(false),[error,setError]=useState('');
 const [rootId,setRootId]=useState(''),[zoom,setZoom]=useState(1),[fdb,setFdb]=useState(false),[mode,setMode]=useState<'physical'|'logical'|'full'>('physical'),[horizontal,setHorizontal]=useState(false),[focus,setFocus]=useState(false),[grouped,setGrouped]=useState(true),[search,setSearch]=useState('');
 const [saved,setSaved]=useState<SavedGraph>(emptyGraph),[selected,setSelected]=useState(''),[selectedEdge,setSelectedEdge]=useState('');
 const [editing,setEditing]=useState<string|null>(null),[manual,setManual]=useState(false),[a,setA]=useState(''),[b,setB]=useState(''),[pa,setPa]=useState(''),[pb,setPb]=useState('');
 const [cached,setCached]=useState(false),[storageWarning,setStorageWarning]=useState(''),[auto,setAuto]=useState(false),[full,setFull]=useState(false);
 const [draft,setDraft]=useState<{id:string;cx:number;y:number}|null>(null);
 const panel=useRef<HTMLDivElement>(null),scroller=useRef<HTMLDivElement>(null),svg=useRef<SVGSVGElement>(null);
 const drag=useRef<{id:string;x:number;y:number;cx:number;top:number;moved:boolean}|null>(null);
 const panning=useRef<{x:number;y:number;left:number;top:number}|null>(null),request=useRef<AbortController|null>(null),busy=useRef(false);
 const scopeKey=`roszetta.topology.v1:${encodeURIComponent(email||'local')}`;
 const storageKey=`${scopeKey}:${encodeURIComponent(group||'')}`;
 useEffect(()=>{let alive=true;api.get<Device[]>('/devices').then(({data:rows})=>{if(!alive)return;const list=[...new Set(rows.map(d=>(d.group_name||'').trim()).filter(Boolean))].sort((x,y)=>x.localeCompare(y,'ru'));setGroups(list);setUngrouped(rows.some(d=>!(d.group_name||'').trim()));const last=readScope(scopeKey);setGroup(last&&(list.includes(last)||last==='__all__'||(last==='__none__'&&rows.some(d=>!(d.group_name||'').trim())))?last:list[0]||'__all__')}).catch(()=>{if(alive)setError('Не удалось получить список оборудования. Проверьте подключение и авторизацию.')});return()=>{alive=false;request.current?.abort()}},[scopeKey]);
 async function scan(target=group,includeFdb=fdb,prior=data){
  if(target===null||busy.current)return;
  const ctrl=new AbortController();request.current=ctrl;busy.current=true;setLoading(true);setError('');
  try{const r=await api.get<TopoOut>('/topology',{params:{...(target==='__all__'?{}:{group:target}),fdb:includeFdb},timeout:300000,signal:ctrl.signal});if(ctrl.signal.aborted||request.current!==ctrl)return;if(prior&&r.data.nodes.length>0&&r.data.nodes.every(n=>n.error)){setError('Ни одно устройство не опрошено. Сохранён предыдущий снимок; проверьте Vault и доступность.');setCached(true);return}setPrevious(prior);setData(r.data);setCached(false);const key=`${scopeKey}:${encodeURIComponent(target)}`;memorySnapshots.set(key,r.data);if(memorySnapshots.size>30)memorySnapshots.delete(memorySnapshots.keys().next().value!);try{if(email)localStorage.setItem(key+':snapshot',JSON.stringify(r.data))}catch{setStorageWarning('Снимок не помещается в хранилище браузера; доступен до перезагрузки страницы.')}}
  catch(e:any){if(!ctrl.signal.aborted)setError(typeof e?.response?.data?.detail==='string'?e.response.data.detail:'Не удалось получить топологию. Повторите опрос выбранного объекта.')}
  finally{if(request.current===ctrl){busy.current=false;if(!ctrl.signal.aborted)setLoading(false)}}
 }
 useEffect(()=>{if(group===null)return;request.current?.abort();busy.current=false;setLoading(false);setError('');setSaved(read(storageKey));setStorageWarning('');const view=readView(storageKey);setRootId(typeof view.rootId==='string'?view.rootId:'');setSelected('');setSelectedEdge('');const snapshot=email?(memorySnapshots.get(storageKey)||readSnapshot(storageKey)):null;setData(snapshot);setCached(Boolean(snapshot));setPrevious(null);setZoom(Number.isFinite(view.zoom)?Math.max(.15,Math.min(2,view.zoom)):1);setHorizontal(view.horizontal===true);setGrouped(view.grouped!==false);setMode(['physical','logical','full'].includes(view.mode)?view.mode:'physical');setManual(false);setEditing(null);setA('');setB('');setPa('');setPb('');setDraft(null);setAuto(false);try{localStorage.setItem(scopeKey+':scope',group)}catch{}if(!snapshot)void scan(group,fdb,null);return()=>{request.current?.abort()};},[group,storageKey]);
 useEffect(()=>{if(!auto||loading||!data||group===null||group==='__all__'||fdb)return;const timer=window.setTimeout(()=>{if(document.visibilityState==='visible')void scan();else setAuto(false)},60000);return()=>window.clearTimeout(timer)},[auto,loading,data,group,fdb]);
 useEffect(()=>{const changed=()=>setFull(document.fullscreenElement===panel.current);document.addEventListener('fullscreenchange',changed);return()=>document.removeEventListener('fullscreenchange',changed)},[]);
 function saveView(patch:Record<string,unknown>){try{localStorage.setItem(storageKey+':view',JSON.stringify({...readView(storageKey),...patch}))}catch{/* graph stays usable */}}
 function zoomTo(v:number){setZoom(v);saveView({zoom:v})}
 function save(next:SavedGraph){setSaved(next);try{localStorage.setItem(storageKey,JSON.stringify(next));setStorageWarning('')}catch{setStorageWarning('Браузер не сохранил схему. Изменения доступны до закрытия страницы.')}}
 const nodes=data?.nodes||[],byId=useMemo(()=>new Map(nodes.map(n=>[n.id,n])),[data]);
 const edges=useMemo(()=>{return mergeManualEdges(data?.edges||[],saved.manual,new Set(byId.keys()),mode)},[data,mode,saved.manual,byId]);
 const lay=useMemo(()=>{
   if(group!=='__all__'||!grouped)return {...layout(nodes,edges.filter(e=>e.evidence==='confirmed'||e.evidence==='probable'||e.evidence==='manual'),rootId||null),bands:[] as {label:string;y:number;h:number}[]};
   const pos=new Map<string,{cx:number;y:number}>(),bands:{label:string;y:number;h:number}[]=[];let y=24,w=640;
   for(const name of [...new Set(nodes.map(n=>n.group||'Без группы'))].sort((x,y)=>x.localeCompare(y,'ru'))){const ids=nodes.filter(n=>(n.group||'Без группы')===name);const idsSet=new Set(ids.map(n=>n.id));const l=layout(ids,edges.filter(e=>(e.evidence==='confirmed'||e.evidence==='probable'||e.evidence==='manual')&&idsSet.has(e.a)&&idsSet.has(e.b)),rootId||null);bands.push({label:name,y,h:l.canvasH+30});l.pos.forEach((p,id)=>pos.set(id,{cx:p.cx,y:p.y+y+30}));w=Math.max(w,l.canvasW);y+=l.canvasH+44;}return {pos,canvasW:w,canvasH:Math.max(y,240),bands};
 },[data,edges,rootId,group,grouped]);
 const positions=new Map(Array.from(lay.pos,([id,p])=>[id,horizontal?{cx:p.y*1.7+NODE_W/2,y:(p.cx-NODE_W/2)*.65+24}:p] as const));for(const [id,p] of Object.entries(saved.positions))if(byId.has(id))positions.set(id,p);if(draft)positions.set(draft.id,draft);
 const width=Math.max(horizontal?0:lay.canvasW,640,...Array.from(positions.values(),p=>p.cx+NODE_W/2+40)),height=Math.max(horizontal?0:lay.canvasH,240,...Array.from(positions.values(),p=>p.y+NODE_H+40));
 const needle=search.trim().toLowerCase();const matches=(n:TNode)=>!needle||[n.label,n.host,n.model,n.group,n.location,n.purpose,n.comment,n.inventory_number].join(' ').toLowerCase().includes(needle);
 const selectedNode=byId.get(selected),edge=edges.find(e=>edgeKey(e)===selectedEdge);
 const edgeTraffic=(e:TEdge)=>{if(cached||e.evidence!=='confirmed')return null;for(const side of ['a','b'] as const){const name=e[`${side}_port`];if(!name)continue;const id=e[side],now=data?.port_samples?.[id]?.[name],old=previous?.port_samples?.[id]?.[name];const rate=portRate(old,now);if(rate)return {...rate,side:`${byId.get(id)?.label||id} / ${name}`}}return null};
 function point(event:ReactPointerEvent<SVGGElement>){const matrix=svg.current?.getScreenCTM();if(!matrix)return null;return new DOMPoint(event.clientX,event.clientY).matrixTransform(matrix.inverse())}
 function pointerDown(e:ReactPointerEvent<SVGGElement>,id:string){if(e.button!==0)return;e.stopPropagation();const p=point(e),start=positions.get(id);if(!p||!start)return;setSelected(id);setSelectedEdge('');drag.current={id,x:p.x,y:p.y,cx:start.cx,top:start.y,moved:false};e.currentTarget.setPointerCapture(e.pointerId)}
 function pointerMove(e:ReactPointerEvent<SVGGElement>){const d=drag.current,p=point(e);if(!d||!p)return;if(Math.hypot(p.x-d.x,p.y-d.y)>3)d.moved=true;if(d.moved)setDraft({id:d.id,cx:Math.max(NODE_W/2,Math.min(width-NODE_W/2,d.cx+p.x-d.x)),y:Math.max(5,Math.min(height-NODE_H,d.top+p.y-d.y))})}
 function pointerEnd(e:ReactPointerEvent<SVGGElement>){const d=drag.current,p=point(e);drag.current=null;setDraft(null);if(d?.moved&&p)save({...saved,positions:{...saved.positions,[d.id]:{cx:Math.max(NODE_W/2,Math.min(width-NODE_W/2,d.cx+p.x-d.x)),y:Math.max(5,Math.min(height-NODE_H,d.top+p.y-d.y))}}})}
 function startManual(e?:TEdge){setEditing(e?edgeKey(e):null);setA(e?.a||'');setB(e?.b||'');setPa(e?.a_port||'');setPb(e?.b_port||'');setManual(true)}
 function deleteManual(e:TEdge){if(!window.confirm('Удалить ручную связь со схемы? Автоматические наблюдения не удаляются.'))return;const key=edgeKey(e);save({...saved,manual:removeManualEdge(saved.manual,key)});if(selectedEdge===key)setSelectedEdge('');if(editing===key){setEditing(null);setManual(false)}}
 function addManual(){if(!byId.has(a)||!byId.has(b)||a===b)return;const e:TEdge={a,b,a_port:pa.trim()||null,b_port:pb.trim()||null,evidence:'manual',protocols:[],speed:null};const change=changeManualEdge(saved.manual,e,editing);if(change.error){setStorageWarning(change.error);return}save({...saved,manual:change.manual});setManual(false);setEditing(null);setSelectedEdge(edgeKey(e));setSelected('');setPa('');setPb('')}
 async function fullscreen(){try{if(document.fullscreenElement===panel.current){await document.exitFullscreen()}else await panel.current?.requestFullscreen()}catch{setError('Полноэкранный режим недоступен в этом браузере.')}}
 const focused=new Set([selected,...edges.filter(e=>e.a===selected||e.b===selected).flatMap(e=>[e.a,e.b])]);
 const counts=(kind:Evidence)=>(kind==='manual'?edges:data?.edges||[]).filter(e=>e.evidence===kind).length;
 const edgeOffsets=new Map<string,number>();
 return <div ref={panel} className="card space-y-3 bg-mk-bg overflow-auto" data-topology-build="1.5.3">
  <div className="flex flex-wrap items-center gap-2"><Network size={16} className="text-mk-accent2"/><b>Интерактивная топология сети</b><span className="text-xs text-mk-mute">Device Visualization v1.5.3</span><button type="button" className="btn-secondary ml-auto" onClick={()=>void fullscreen()}>{full?'Выйти из полного экрана':'Полный экран'}</button><button type="button" className="btn-primary flex items-center gap-1" disabled={loading||group===null} onClick={()=>void scan()}><RefreshCw size={14}/>{loading?'Опрос устройств…':'Обновить топологию'}</button></div>
  <div className="flex flex-wrap items-center gap-2 text-xs"><label>Объект <select className="input !w-auto" value={group||''} disabled={loading} onChange={e=>setGroup(e.target.value)}>{groups.map(g=><option key={g}>{g}</option>)}{ungrouped&&<option value="__none__">Без объекта</option>}<option value="__all__">Все устройства</option></select></label><label>Корень <select className="input !w-auto" value={rootId} disabled={group==='__all__'&&grouped} onChange={e=>{setRootId(e.target.value);saveView({rootId:e.target.value});save({...saved,positions:{}})}}><option value="">Авто</option>{nodes.map(n=><option key={n.id} value={n.id}>{n.label}</option>)}</select></label><input className="input !w-auto" placeholder="Имя, IP, модель…" value={search} onChange={e=>setSearch(e.target.value)}/>{group==='__all__'&&<label><input type="checkbox" checked={grouped} onChange={e=>{setGrouped(e.target.checked);setHorizontal(false);saveView({grouped:e.target.checked,horizontal:false});save({...saved,positions:{}})}}/> Разложить по объектам</label>}<label><input type="checkbox" checked={fdb} disabled={loading} onChange={e=>{setFdb(e.target.checked);if(e.target.checked)setAuto(false)}}/> Анализ MAC при следующем опросе</label><label>Режим <select className="input !w-auto" value={mode} onChange={e=>{setMode(e.target.value as typeof mode);saveView({mode:e.target.value});setSelectedEdge('')}}><option value="physical">Физическая</option><option value="logical">Логическая</option><option value="full">Полная (MAC)</option></select></label><label><input type="checkbox" checked={horizontal} disabled={group==='__all__'&&grouped} onChange={e=>{setHorizontal(e.target.checked);saveView({horizontal:e.target.checked});save({...saved,positions:{}})}}/> Горизонтально</label><label><input type="checkbox" checked={focus} onChange={e=>setFocus(e.target.checked)}/> Соседи выбранного</label><label title="Для одного объекта, без MAC-анализа: через 60 секунд после опроса"><input type="checkbox" checked={auto} disabled={fdb||group===null||group==='__all__'} onChange={e=>setAuto(e.target.checked)}/> Автообновление (60 с)</label></div>
  <div className="flex flex-wrap gap-3 text-xs items-center"><span>Устройств: {nodes.length} · показано связей: {edges.length} · автоматических: {data?.edges.length||0}</span>{(Object.keys(evidenceLabel) as Evidence[]).map(k=><span key={k} style={{color:evidenceColor[k]}}>● {evidenceLabel[k]}: {counts(k)}</span>)}<span className="text-mk-mute">{data?`${cached?'Сохранённый снимок (не живой статус)':'Снимок'}: ${new Date(data.collected_at).toLocaleString()}`:'Нет снимка'}</span></div>
  {mode==='full'&&!fdb&&<p className="text-xs text-mk-mute">Для свежих MAC-путей включите анализ MAC и обновите топологию.</p>}
  <div className="flex flex-wrap items-center gap-2"><button type="button" className="btn-secondary" onClick={()=>zoomTo(Math.max(.25,zoom-.15))}>−</button><span className="text-xs">{Math.round(zoom*100)}%</span><button type="button" className="btn-secondary" onClick={()=>zoomTo(Math.min(2,zoom+.15))}>+</button><button type="button" className="btn-secondary" onClick={()=>{zoomTo(1);if(scroller.current){scroller.current.scrollTop=0;scroller.current.scrollLeft=0}}}>100%</button><button type="button" className="btn-secondary" onClick={()=>zoomTo(Math.max(.15,Math.min(1,(scroller.current?.clientWidth||width)/width)))}>Вписать по ширине</button><button type="button" className="btn-secondary" onClick={()=>save({...saved,positions:{}})}>Автораскладка</button><button type="button" className="btn-secondary" disabled={nodes.length<2} onClick={()=>startManual()}>+ Ручная связь</button></div>
  {saved.manual.length>0&&<details className="border border-mk-border rounded p-2"><summary className="cursor-pointer">Ручные связи ({saved.manual.length}) — управление</summary><div className="max-h-60 overflow-auto space-y-1 mt-2">{saved.manual.map(e=><div key={edgeKey(e)} className="flex flex-wrap items-center gap-2 border-b border-mk-border py-1 text-xs"><span className="flex-1">{byId.get(e.a)?.label||e.a} ({e.a_port||'—'}) ↔ {byId.get(e.b)?.label||e.b} ({e.b_port||'—'})</span><button type="button" className="btn-secondary" disabled={!byId.has(e.a)||!byId.has(e.b)} onClick={()=>startManual(e)}>Изменить</button><button type="button" className="btn-secondary text-red-400" onClick={()=>deleteManual(e)}>Удалить</button></div>)}</div></details>}
  {manual&&<div className="border border-mk-border rounded p-3 space-y-2"><b>{editing?'Изменить ручную связь':'Новая ручная связь'}</b><p className="text-xs text-mk-mute">Связь добавляется только на схему, не в конфигурацию MikroTik. Сохранение в этом браузере.</p><div className="grid grid-cols-2 gap-2"><select className="input" value={a} onChange={e=>setA(e.target.value)}><option value="">Устройство A</option>{nodes.map(n=><option key={n.id} value={n.id}>{n.label}</option>)}</select><select className="input" value={b} onChange={e=>setB(e.target.value)}><option value="">Устройство B</option>{nodes.filter(n=>n.id!==a).map(n=><option key={n.id} value={n.id}>{n.label}</option>)}</select><input className="input" placeholder="Порт A (необязательно)" value={pa} maxLength={100} onChange={e=>setPa(e.target.value)}/><input className="input" placeholder="Порт B (необязательно)" value={pb} maxLength={100} onChange={e=>setPb(e.target.value)}/></div><button className="btn-primary" type="button" disabled={!a||!b||a===b} onClick={addManual}>{editing?'Сохранить изменения':'Добавить на схему'}</button><button type="button" className="btn-secondary ml-2" onClick={()=>{setManual(false);setEditing(null)}}>Отмена</button></div>}
  {error&&<p className="text-mk-err text-sm" role="alert">{error}</p>}{storageWarning&&<p className="text-mk-warn text-xs">{storageWarning}</p>}{loading&&<p className="text-mk-mute text-xs">Опрос выполняется параллельно, до 8 устройств. Не запускайте повторный опрос до завершения. Старая схема остаётся видимой.</p>}
  {data&&<div ref={scroller} className="overflow-auto rounded border border-mk-border bg-mk-bg" style={{height:full?'76vh':'min(62vh, 780px)',touchAction:'none',cursor:'grab'}} onPointerDown={e=>{if(e.button!==0|| (e.target as Element).closest('[data-graph-target]'))return;panning.current={x:e.clientX,y:e.clientY,left:e.currentTarget.scrollLeft,top:e.currentTarget.scrollTop};e.currentTarget.setPointerCapture(e.pointerId)}} onPointerMove={e=>{const p=panning.current;if(p){e.currentTarget.scrollLeft=p.left+p.x-e.clientX;e.currentTarget.scrollTop=p.top+p.y-e.clientY}}} onPointerUp={()=>{panning.current=null}} onLostPointerCapture={()=>{panning.current=null}}>
   <svg ref={svg} width={width*zoom} height={height*zoom} viewBox={`0 0 ${width} ${height}`} style={{display:'block',maxWidth:'none',userSelect:'none'}}>
    {lay.bands.map(band=><g key={band.label}><rect x={8} y={band.y} width={lay.canvasW-16} height={band.h} rx={9} fill="#172130" fillOpacity={.3} stroke="#344258" strokeDasharray="5 5"/><text x={20} y={band.y+19} fill="#9caec4" fontSize={13}>{band.label}</text></g>)}
    {edges.map((e,i)=>{const A=positions.get(e.a),B=positions.get(e.b);if(!A||!B)return null;const pair=[e.a,e.b].sort().join('|');const offset=edgeOffsets.get(pair)||0;edgeOffsets.set(pair,offset+1);const off=offset===0?0:(offset%2?1:-1)*Math.ceil(offset/2)*14;const x1=A.cx+off,x2=B.cx+off,y1=A.y+(A.y<=B.y?NODE_H:0),y2=B.y+(A.y>=B.y?NODE_H:0),mid=(y1+y2)/2;const path=horizontal?`M${A.cx+(A.cx<=B.cx?NODE_W/2:-NODE_W/2)} ${A.y+NODE_H/2+off} C${(A.cx+B.cx)/2} ${A.y+NODE_H/2+off},${(A.cx+B.cx)/2} ${B.y+NODE_H/2+off},${B.cx+(A.cx<=B.cx?-NODE_W/2:NODE_W/2)} ${B.y+NODE_H/2+off}`:Math.abs(A.y-B.y)<2?`M${x1} ${A.y+NODE_H} C${x1} ${A.y+NODE_H+52+off},${x2} ${B.y+NODE_H+52+off},${x2} ${B.y+NODE_H}`:`M${x1} ${y1} C${x1} ${mid},${x2} ${mid},${x2} ${y2}`;const key=edgeKey(e),active=selectedEdge===key,traffic=edgeTraffic(e),color=evidenceColor[e.evidence]||'#64748b';const opacity=focus&&selected&&e.a!==selected&&e.b!==selected ? .08 : matches(byId.get(e.a)!)||matches(byId.get(e.b)!)?1:.15;return <g key={key+i} data-graph-target="edge" opacity={opacity} role="button" tabIndex={0} aria-label={`${byId.get(e.a)?.label} — ${byId.get(e.b)?.label}: ${evidenceLabel[e.evidence]}`} onClick={()=>{setSelectedEdge(key);setSelected('')}} onKeyDown={event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();setSelectedEdge(key);setSelected('')}}} style={{cursor:'pointer'}}><title>{[evidenceLabel[e.evidence],e.a_port,e.b_port,e.link_state==='down'?'Порт без линка':null,e.speed_conflict?'Скорости не совпадают':e.speed,traffic?`RX ${bps(traffic.rx)} / TX ${bps(traffic.tx)} (${traffic.side})`:null].filter(Boolean).join(' · ')}</title><path d={path} stroke="transparent" strokeWidth={16} fill="none"/><path d={path} stroke={e.link_state==='down'?'#ef4444':color} strokeWidth={active?4:2} strokeDasharray={e.evidence==='confirmed'?undefined:e.evidence==='fdb'?'3 6':'8 5'} fill="none" pointerEvents="none"/>{active&&!horizontal&&<g fill="#bac6d6" stroke="#0b1120" strokeWidth={3} paintOrder="stroke" fontSize={10} textAnchor="middle" pointerEvents="none"><text x={x1+off} y={y1+(A.y<=B.y?13:-7)}>{e.a_port||'?'}</text><text x={x2+off} y={y2+(A.y<=B.y?-7:13)}>{e.b_port||'?'}</text>{e.evidence!=='fdb'&&<text x={(x1+x2)/2+off} y={Math.abs(A.y-B.y)<2?A.y+NODE_H+43+off:mid-6}>{e.link_state==='down'?'Link Down':e.speed_conflict?'Скорости различаются':e.speed?`${e.speed}bps`:''}{traffic?` · ↓${bps(traffic.rx)} ↑${bps(traffic.tx)}`:''}</text>}</g>}</g>})}
    {nodes.map(n=>{const p=positions.get(n.id);if(!p)return null;const x=p.cx-NODE_W/2;const status=cached?'#94a3b8':n.status==='up'?'#22c55e':n.status==='down'?'#ef4444':'#94a3b8';const preview=resolveDevicePreview(n.model,n.kind);return <g key={n.id} data-graph-target="node" role="button" tabIndex={0} aria-label={`${n.label} ${n.host}`} opacity={focus&&selected&&!focused.has(n.id) ? .15 :matches(n)?1:.2} style={{cursor:'move',touchAction:'none'}} onPointerDown={e=>pointerDown(e,n.id)} onPointerMove={pointerMove} onPointerUp={pointerEnd} onPointerCancel={()=>{drag.current=null;setDraft(null)}} onLostPointerCapture={()=>{drag.current=null;setDraft(null)}} onDoubleClick={()=>navigate(`/devices/${n.device_id}`)} onKeyDown={e=>{if(e.key==='Enter'){setSelected(n.id);setSelectedEdge('')}}}><title>{[n.label,n.host,n.model,n.group,n.location,n.purpose,n.comment,n.inventory_number,n.error,...(n.warnings||[])].filter(Boolean).join('\n')}</title><rect x={x} y={p.y} width={NODE_W} height={NODE_H} rx={8} fill="#151e2c" stroke={selected===n.id?'#60a5fa':'#3b4a60'} strokeWidth={selected===n.id?2.5:1.4}/><image href={`${import.meta.env.BASE_URL}device-previews/${preview}.svg`} x={x+30} y={p.y+6} width={150} height={40} preserveAspectRatio="xMidYMid meet"/><circle cx={x+NODE_W-13} cy={p.y+13} r={4} fill={status}/><text x={p.cx} y={p.y+59} fontSize={12} fontWeight={600} textAnchor="middle" fill="#e5e7eb">{cut(n.label,30)}</text><text x={p.cx} y={p.y+74} fontSize={10} textAnchor="middle" fill="#9caec4">{cut([n.model,n.host].filter(Boolean).join(' · '),35)}</text><text x={p.cx} y={p.y+86} fontSize={9} textAnchor="middle" fill={n.error?'#eab308':'#8294ad'}>{n.error?'Опрос неполный':cut(n.location||n.group||'Без объекта',36)}</text></g>})}
   </svg></div>}
   {selectedNode&&<div className="border border-mk-border rounded p-3 flex flex-wrap gap-3 items-center text-sm"><b>{selectedNode.label}</b><span>{selectedNode.model} · {selectedNode.host}</span><span className="text-mk-mute">{selectedNode.group||'Без объекта'}</span>{[selectedNode.location,selectedNode.purpose,selectedNode.comment,selectedNode.inventory_number].filter(Boolean).map((v,i)=><span className="text-mk-mute whitespace-pre-wrap" key={i}>{v}</span>)}{selectedNode.error&&<span className="text-mk-warn">{selectedNode.error}</span>}<button type="button" className="btn-primary ml-auto" onClick={()=>navigate(`/devices/${selectedNode.device_id}`)}>Открыть устройство</button></div>}
   {edge&&<div className="border border-mk-border rounded p-3 space-y-2 text-sm"><div className="flex flex-wrap gap-2 items-center"><b>{byId.get(edge.a)?.label} ↔ {byId.get(edge.b)?.label}</b><span style={{color:evidenceColor[edge.evidence]}}>{evidenceLabel[edge.evidence]}</span>{edge.evidence==='manual'&&<><button type="button" className="btn-secondary ml-auto" onClick={()=>startManual(edge)}>Изменить связь</button><button type="button" className="btn-secondary text-red-400" onClick={()=>deleteManual(edge)}>Удалить со схемы</button></>}</div><p>{edge.a_port||'Порт неизвестен'} ↔ {edge.b_port||'Порт неизвестен'} · {edge.speed_conflict?'Скорости концов различаются':edge.speed?`${edge.speed}bps`:'Скорость неизвестна'}</p><p className="text-mk-mute">{edge.protocols?.join(', ')||'Протокол не определён'} · {edge.link_state==='down'?'Порт без линка':edge.link_state==='up'?'Оба порта Link UP':edge.link_state==='partial'?'Link UP на известной стороне':'Состояние линка неизвестно'}</p>{(()=>{const t=edgeTraffic(edge);return t?<p>Средний трафик: RX {bps(t.rx)} · TX {bps(t.tx)} · {Math.round(t.seconds)} с · {t.side}</p>:<p className="text-mk-mute">Трафик: нужны два сопоставимых снимка (обновите топологию). Только для двусторонних LLDP-связей.</p>})()}</div>}
   {!!data?.unmanaged?.length&&<details className="text-xs"><summary>LLDP-соседи, не сопоставленные с оборудованием объекта ({data.unmanaged.length})</summary>{data.unmanaged.map((n,i)=><div className="py-1 border-b border-mk-border" key={i}>{byId.get(n.device)?.label} / {n.port} → {n.identity||n.mac} · {n.remote_port||'порт неизвестен'} · {n.address||n.mac||'адрес неизвестен'}</div>)}</details>}
   {data&&edges.length===0&&<p className="text-xs text-mk-mute">В выбранном режиме нет связей. Переключитесь на логическую схему или проверьте /ip/neighbor/print и настройки Neighbor Discovery. Оборудование без обнаруженных соседей остаётся на схеме.</p>}
   {nodes.some(n=>n.error||n.warnings?.length)&&<details className="text-xs text-mk-warn"><summary className="cursor-pointer">Неполный опрос: {nodes.filter(n=>n.error||n.warnings?.length).length} устройств</summary>{nodes.filter(n=>n.error||n.warnings?.length).map(n=><p key={n.id}>{n.label}: {[n.error,...(n.warnings||[])].filter(Boolean).join('; ')}</p>)}</details>}
   <p className="text-xs text-mk-mute">Перетаскивайте узлы и пустое поле; двойной клик открывает устройство. Положение, параметры отображения, ручные связи и последний снимок сохраняются в браузере для текущего пользователя и объекта. Сохранённый снимок показывает прошлое состояние; обновите его вручную при необходимости. Сплошная линия означает взаимное LLDP с известными портами без конкурирующих пар (не гарантия прямого кабеля), пунктир — односторонний LLDP, наблюдение или гипотеза, не доказательство прямого кабеля. Красная линия — один из известных портов без линка. Трафик — среднее между двумя опросами; не непрерывное измерение. Конфигурация RouterOS не меняется.</p>
 </div>
}
