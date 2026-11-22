export interface PortSample {rx:string|null;tx:string|null;running:boolean|null;speed:string|null;sampled_at_ms:number|null;uptime:number|null}
export type Evidence='confirmed'|'probable'|'neighbor'|'fdb'|'manual'|'vpn';
export interface TopologyEdge {a:string;b:string;a_port:string|null;b_port:string|null;evidence:Evidence;protocols:string[];speed:string|null;speed_conflict?:boolean;link_state?:'up'|'down'|'partial'|'unknown'}
export type Positions=Record<string,{cx:number;y:number}>;
export interface SavedGraph {positions:Positions;manual:TopologyEdge[]}
export const emptyGraph=():SavedGraph=>({positions:{},manual:[]});
export function loadGraph(raw:string|null):SavedGraph {
  try {
    const v=JSON.parse(raw||'null');if(!v||typeof v!=='object')return emptyGraph();
    const positions:Positions={};
    for(const [k,val] of Object.entries(v.positions||{})){
      const p=val as {cx:number;y:number};if(/^d\d+$/.test(k)&&p&&Number.isFinite(p.cx)&&Number.isFinite(p.y)&&p.cx>=0&&p.y>=0&&p.cx<50000&&p.y<50000)positions[k]=p;
    }
    const manual:TopologyEdge[]=Array.isArray(v.manual)?v.manual.filter((e:TopologyEdge)=>e&&e.evidence==='manual'&&/^d\d+$/.test(e.a)&&/^d\d+$/.test(e.b)&&e.a!==e.b&&(e.a_port===null||typeof e.a_port==='string')&&(e.b_port===null||typeof e.b_port==='string')).slice(0,500).map((e:TopologyEdge)=>({a:e.a,b:e.b,a_port:e.a_port,b_port:e.b_port,evidence:'manual',protocols:[],speed:null})):[];
    return {positions,manual};
  }catch{return emptyGraph()}
}
export function edgeKey(e:TopologyEdge){return (e.evidence==='vpn'?'vpn:':'')+JSON.stringify([[e.a,e.a_port],[e.b,e.b_port]].sort((a,b)=>String(a[0]).localeCompare(String(b[0]))));}
export function portRate(old:PortSample|undefined,now:PortSample|undefined):{rx:number;tx:number;seconds:number}|null{
  if(!old||!now||!old.running||!now.running||old.uptime==null||now.uptime==null||old.sampled_at_ms==null||now.sampled_at_ms==null)return null;
  const seconds=(now.sampled_at_ms-old.sampled_at_ms)/1000;
  if(seconds<1||seconds>600||now.uptime<old.uptime||Math.abs(now.uptime-old.uptime-seconds)>8)return null;
  if([old.rx,old.tx,now.rx,now.tx].some(x=>typeof x!=='string'||!/^\d+$/.test(x)))return null;
  const rx=BigInt(now.rx!)-BigInt(old.rx!),tx=BigInt(now.tx!)-BigInt(old.tx!);
  if(rx<0n||tx<0n)return null;
  const r=Number(rx)*8/seconds,t=Number(tx)*8/seconds;
  return Number.isFinite(r)&&Number.isFinite(t)?{rx:r,tx:t,seconds}:null;
}
export const evidenceLabel:Record<Evidence,string>={confirmed:'Двусторонний LLDP',probable:'Односторонний LLDP (кандидат)',vpn:'L2TP (логическая связь)',neighbor:'Наблюдение соседа',fdb:'Путь по MAC (не физическая связь)',manual:'Ручная связь'};
export const evidenceColor:Record<Evidence,string>={confirmed:'#22c55e',probable:'#38bdf8',vpn:'#a78bfa',neighbor:'#60a5fa',fdb:'#eab308',manual:'#c084fc'};

export type GraphMode='physical'|'logical'|'full';
export function visibleEdges(edges:TopologyEdge[],mode:GraphMode){return edges.filter(e=>mode==='full'||e.evidence==='confirmed'||e.evidence==='probable'||e.evidence==='manual'||(mode==='logical'&&(e.evidence==='neighbor'||e.evidence==='vpn')));}

// Snapshot is a last-observed graph, never a live guarantee. Reject malformed or old-schema cache.
export function parseTopologySnapshot<T>(raw:string|null):T|null {
  try{
    const v=JSON.parse(raw||'null');
    if(!v||!Array.isArray(v.nodes)||!Array.isArray(v.edges)||!v.port_samples||typeof v.port_samples!=='object'||!Number.isFinite(Date.parse(v.collected_at)))return null;
    if(v.nodes.some((n:any)=>!n||typeof n.id!=='string'||typeof n.label!=='string'||!Number.isFinite(n.device_id)))return null;
    if(v.edges.some((e:any)=>!e||typeof e.a!=='string'||typeof e.b!=='string'||!Object.prototype.hasOwnProperty.call(evidenceLabel,e.evidence)))return null;
    return v as T;
  }catch{return null}
}
export function mergeManualEdges(detected:TopologyEdge[],manual:TopologyEdge[],ids:Set<string>,mode:GraphMode){
 const active=manual.filter(e=>ids.has(e.a)&&ids.has(e.b));
 const keys=new Set(active.map(edgeKey));
 return [...visibleEdges(detected,mode).filter(e=>!keys.has(edgeKey(e))),...active];
}
export function changeManualEdge(manual:TopologyEdge[],edge:TopologyEdge,editing:string|null){
 const rest=manual.filter(e=>edgeKey(e)!==editing);
 if(rest.some(e=>edgeKey(e)===edgeKey(edge)))return {error:'Такая ручная связь уже существует.',manual};
 if(rest.length>=500)return {error:'Достигнут предел 500 ручных связей.',manual};
 return {error:'',manual:[...rest,edge]};
}
export function removeManualEdge(manual:TopologyEdge[],key:string){return manual.filter(e=>edgeKey(e)!==key)}
