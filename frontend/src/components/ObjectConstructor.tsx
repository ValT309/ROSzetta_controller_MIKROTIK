import {defaultBridge,bridgeNetwork,type BridgeLan} from './objectBridge';
import {buildHardening} from './objectHardening';
import {profiles,profileLabel,vpnServers,commonDefaults,networkRoles,recommendedRoles,planProfile} from './objectProfiles';
import ObjectPreflight from './ObjectPreflight';
import {buildDns} from './objectDns';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Download, Plus, Trash2, Network, Shield, Cable, Wifi, Server, Route, Eye, AlertTriangle } from 'lucide-react';

import { api } from '../api/client';
import { buildServices, defaultServices, type Services, type WifiNet } from './objectServices';
import { buildRouting, rosQuote, validIPv4, loopbackIP } from './objectRouting';

type Vlan = { id: string; name: string; subnet: string; gateway: string; dhcp: boolean; poolStart: string; poolEnd: string; tagged: string; untagged: string };
type Port = { name: string; role: 'wan' | 'lan' | 'trunk' | 'hybrid' | 'unused'; pvid: string };
type WanMode = 'pppoe' | 'static' | 'dhcp';

const inputClass = 'input w-full';
const labelClass = 'block text-xs text-mk-mute mb-1';
const cardClass = 'card p-3 space-y-3';
const defaultVlan = (): Vlan => ({ id: '60', name: 'video', subnet: '', gateway: '', dhcp: true, poolStart: '', poolEnd: '', tagged: '', untagged: '' });

function canonical(value:unknown):string {
  return JSON.stringify(value,(_key,v)=>v&&typeof v==='object'&&!Array.isArray(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])):v) ?? '';
}
function safeName(value: string) { return value.trim().replace(/[^a-zA-Z0-9_-]+/g, '-').replace(/^-|-$/g, '') || 'object'; }
function validCidr(value: string) { return /^([0-9]|[12]\d|3[0-2])$/.test(value.split('/')[1] || '') && value.split('/').length === 2 && validIPv4(value.split('/')[0]); }
function validIp(value: string) { return validIPv4(value.trim()); }

const Field = ({ label, value, onChange, placeholder = '', type = 'text', invalid = false }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; type?: string; invalid?: boolean }) => {
  const [show, setShow] = useState(false);
  return <div><label><span className={labelClass}>{label}</span><input className={inputClass + (invalid ? ' !border-red-500' : '')} aria-invalid={invalid} type={type === 'password' && show ? 'text' : type} value={value} placeholder={placeholder} onChange={e => onChange(e.target.value)} /></label>{type === 'password' && <button type="button" className="text-xs text-mk-mute mt-1" onClick={() => setShow(x => !x)}>{show ? 'Скрыть пароль' : 'Показать пароль'}</button>}</div>;
};
const PortPicker = ({label,value,options,onChange}:{label:string;value:string;options:string[];onChange:(v:string)=>void}) => {
  const selected = value.split(',').map(x=>x.trim()).filter(Boolean);
  return <fieldset className="rounded border border-mk-border p-2"><legend className={labelClass}>{label}</legend>{[...new Set([...options,...selected])].map(n=><label key={n} className="flex gap-2 items-center text-xs py-1"><input type="checkbox" checked={selected.includes(n)} disabled={!options.includes(n)&&!selected.includes(n)} onChange={e=>onChange((e.target.checked?[...selected,n]:selected.filter(x=>x!==n)).join(','))}/>{n}{!options.includes(n)&&' (проверьте назначение)'}</label>)}{!options.length&&!selected.length&&<span className="text-xs text-mk-mute">Нет подходящих портов</span>}</fieldset>;
};
import { suggestPool } from './objectRouting';

export default function ObjectConstructor() {
  const [profile, setProfile] = useState('office');
  const [profileIds,setProfileIds]=useState<Record<string,string>>({});
  const [profileError,setProfileError]=useState('');
  const [name, setName] = useState('');
  const [model, setModel] = useState('hAP ax²');
  const [identity, setIdentity] = useState('');
  const [loopbackAddress,setLoopbackAddress]=useState('');
  const [wanMode, setWanMode] = useState<WanMode>('pppoe');
  const [wanPort, setWanPort] = useState('ether1');
  const [pppoeUser, setPppoeUser] = useState('');
  const [pppoePassword, setPppoePassword] = useState('');
  const [wanAddress, setWanAddress] = useState('');
  const [wanGateway, setWanGateway] = useState('');
  const [ports, setPorts] = useState<Port[]>([
    { name: 'ether1', role: 'wan', pvid: '1' }, { name: 'ether2', role: 'lan', pvid: '1' },
    { name: 'ether3', role: 'lan', pvid: '1' }, { name: 'ether4', role: 'trunk', pvid: '1' },
    { name: 'ether5', role: 'lan', pvid: '1' },
  ]);
  const [bridgeLan,setBridgeLan]=useState<BridgeLan>(defaultBridge);
  const patchBridge=(p:Partial<BridgeLan>)=>setBridgeLan(b=>({...b,...p}));
  const bridgeNet=bridgeNetwork(bridgeLan);
  const [vlans, setVlans] = useState<Vlan[]>([defaultVlan()]);
  const [dns, setDns] = useState('77.88.8.8,8.8.4.4');
  const [l2tp, setL2tp] = useState([
    { enabled: false, name: 'l2tp-central-1', server: vpnServers[0] as string, user: '', password: '', ipsecSecret: '', ospfKey: '', cost: '10' },
    { enabled: false, name: 'l2tp-central-2', server: vpnServers[1] as string, user: '', password: '', ipsecSecret: '', ospfKey: '', cost: '100' },
  ]);
  const [ospfRouterId, setOspfRouterId] = useState('');
  const [ospfArea, setOspfArea] = useState('backbone');
  const [firewallProfile, setFirewallProfile] = useState('standard');
  const [management, setManagement] = useState('');
  const [guests, setGuests] = useState('');
  const [corporate, setCorporate] = useState('');
  const [services,setServices]=useState<Services>(()=>({...defaultServices(),...commonDefaults}));
  const patchServices=(p:Partial<Services>)=>setServices(old=>({...old,...p}));
  const patchWifi=(key:'corpWifi'|'guestWifi',p:Partial<WifiNet>)=>setServices(old=>({...old,[key]:{...old[key],...p}}));
  const [wifiEnabled, setWifiEnabled] = useState(false);
  const [wifiSsid, setWifiSsid] = useState('');
  const [wifiPassword, setWifiPassword] = useState('');
  const [preview, setPreview] = useState(false);


  const draft = {bridgeLan,profile, name, model, identity, loopbackAddress, wanMode, wanPort, pppoeUser, pppoePassword, wanAddress, wanGateway, ports, vlans, dns, l2tp, ospfRouterId, ospfArea, firewallProfile, management, guests, corporate, wifiEnabled, wifiSsid, wifiPassword, services};
  type Draft = typeof draft;
  type Site = {id:string;name:string;model:string;profile:string;revision:number;updated_at:string};
  const draftKey = canonical(draft);
  const defaults = useRef<Draft>(draft);
  const [savedKey, setSavedKey] = useState(draftKey);
  const [current, setCurrent] = useState<Site|null>(null);
  const [sites, setSites] = useState<Site[]>([]);
  type Version = {revision:number;updated_at:string};
  const [history,setHistory]=useState<{site:Site;versions:Version[]}|null>(null);
  const [comparison,setComparison]=useState<{revision:number;changes:{field:string;before:string;after:string}[]}|null>(null);
  const [search, setSearch] = useState('');
  const [autoSave, setAutoSave] = useState(true);
  const [busy, setBusy] = useState(false);
  const [loadingForm, setLoadingForm] = useState(false);
  const [saveError, setSaveError] = useState('');
  const [listError, setListError] = useState('');
  const [message, setMessage] = useState('');
  const busyRef = useRef(false);
  const pendingId = useRef('');
  const dirty = draftKey !== savedKey;
  const explain = (e: any) => e?.response?.status === 423 ? 'Vault заблокирован. Разблокируйте хранилище и повторите сохранение.' : e?.response?.status === 409 && e?.response?.data?.detail === 'Loopback already assigned' ? 'Loopback уже назначен другому объекту. Измените адрес и повторите сохранение.' : e?.response?.status === 409 ? 'Объект изменён в другом окне или удалён. Откройте его заново или создайте копию.' : 'Запрос не выполнен. Проверьте соединение и журнал backend.';
  const refreshSites = async () => {
    try { const {data} = await api.get<Site[]>('/object-constructor/sites'); setSites(data); setListError(''); }
    catch(e) { setListError(explain(e)); }
  };
  useEffect(() => { void refreshSites(); }, []);
  const loadDraft = (d: Draft) => {
    setProfile(d.profile);setProfileIds({});setProfileError('');
    setName(d.name);
    setModel(d.model);
    setIdentity(d.identity);
    setLoopbackAddress(d.loopbackAddress||'');
    setWanMode(d.wanMode);
    setWanPort(d.wanPort);
    setPppoeUser(d.pppoeUser);
    setPppoePassword(d.pppoePassword);
    setWanAddress(d.wanAddress);
    setWanGateway(d.wanGateway);
    setPorts(d.ports);
    setVlans(d.vlans);
    setBridgeLan({...defaultBridge(),...d.bridgeLan});
    setDns(d.dns);
    setL2tp(d.l2tp);
    setOspfRouterId(d.ospfRouterId);
    setOspfArea(d.ospfArea);
    setFirewallProfile(d.firewallProfile);
    setManagement(d.management);
    setGuests(d.guests);
    setCorporate(d.corporate);
    setServices({...defaultServices(),splitDns:false,...d.services});
    setWifiEnabled(d.wifiEnabled);
    setWifiSsid(d.wifiSsid);
    setWifiPassword(d.wifiPassword);
    setPreview(false);
  };
  const start = () => { if (busyRef.current) return false; busyRef.current=true;setBusy(true);return true; };
  const finish = () => {busyRef.current=false;setBusy(false);setLoadingForm(false);};
  const makeId = () => {
    const b = crypto.getRandomValues(new Uint8Array(16)); b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;
    const h=Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;
  };
  const save = async () => {
    if (!start()) return;
    setSaveError('');setMessage('');
    try {
      const id=current?.id || pendingId.current || (pendingId.current=makeId());
      const {data}=await api.put<Site>(`/object-constructor/sites/${id}`,{revision:current?.revision||0,draft:JSON.parse(draftKey)});
      setCurrent(data);setSavedKey(draftKey);setMessage('Черновик сохранён');await refreshSites();
    } catch(e) {setSaveError(explain(e));} finally {finish();}
  };
  useEffect(() => {
    if (!autoSave || !dirty || busy || saveError) return;
    const timer=setTimeout(()=>{void save();},1200);
    return ()=>clearTimeout(timer);
  },[autoSave,dirty,draftKey,busy,saveError,current?.revision]);
  useEffect(()=>{
    if (!dirty && !busy) return;
    const warn=(e:BeforeUnloadEvent)=>{e.preventDefault();e.returnValue='';};
    window.addEventListener('beforeunload',warn);return ()=>window.removeEventListener('beforeunload',warn);
  },[dirty,busy]);
  const canSwitch=()=>!dirty || window.confirm('Есть несохранённые изменения. Продолжить без сохранения?');
  const detachDraft=()=>{if(busyRef.current||!window.confirm('Сохранить текущие параметры в отдельный черновик? Пароли останутся в нём.'))return;setCurrent(null);pendingId.current='';setSavedKey('');setSaveError('');setMessage('Новый черновик: нажмите «Сохранить» или дождитесь автосохранения');};
  const reset = () => {if(busyRef.current||!canSwitch())return;loadDraft(defaults.current);setCurrent(null);pendingId.current='';setSavedKey(canonical(defaults.current));setSaveError('');setMessage('');};
  const openSite=async(site:Site,copy=false)=>{
    if(busyRef.current||!canSwitch()||!start())return;
    setLoadingForm(true);
    try {
      const {data}=await api.get<Site & {draft:Draft}>(`/object-constructor/sites/${site.id}`);
      const d=copy?{...data.draft,name:(data.draft.name.slice(0,190)+' — копия'),identity:'',loopbackAddress:'',pppoePassword:'',wifiPassword:'',services:{...(data.draft.services||defaultServices()),corpWifi:{...(data.draft.services||defaultServices()).corpWifi,password:''},guestWifi:{...(data.draft.services||defaultServices()).guestWifi,password:''},radiusSecret:'',snmpAuthPassword:'',snmpEncryptionPassword:''},l2tp:data.draft.l2tp.map(t=>({...t,password:'',ipsecSecret:'',ospfKey:''}))}:data.draft;
      loadDraft(d);setCurrent(copy?null:data);pendingId.current='';setSavedKey(copy?canonical(defaults.current):canonical({...d,bridgeLan:{...defaultBridge(),...d.bridgeLan},loopbackAddress:d.loopbackAddress||'',services:d.services||defaultServices()}));setSaveError('');setMessage(copy?'Копия: секреты и Loopback очищены':'Объект открыт');
    } catch(e){setListError(explain(e));}finally{finish();}
  };
  const removeSite=async(site:Site)=>{
    if(busyRef.current||!window.confirm(`Удалить «${site.name}»?`)||(current?.id===site.id&&!canSwitch())||!start())return;
    setLoadingForm(true);
    try {await api.delete(`/object-constructor/sites/${site.id}`,{params:{revision:site.revision}});if(current?.id===site.id){loadDraft(defaults.current);setCurrent(null);pendingId.current='';setSavedKey(canonical(defaults.current));setSaveError('');setMessage('');}await refreshSites();}
    catch(e){setListError(explain(e));}finally{finish();}
  };

  const showHistory=async(site:Site)=>{
    if(!start())return;
    setHistory(null);setComparison(null);setListError('');
    try{const {data}=await api.get<Version[]>(`/object-constructor/sites/${site.id}/versions`);setHistory({site,versions:data});}
    catch(e){setListError(explain(e));}finally{finish();}
  };
  const compareDrafts=(a:Draft,b:Draft)=>{
    const changes:{field:string;before:string;after:string}[]=[];
    const walk=(x:any,y:any,path:string)=>{
      if(canonical(x)===canonical(y))return;
      if((x!==null&&typeof x==='object')||(y!==null&&typeof y==='object')){
        const keys=new Set([...Object.keys(x||{}),...Object.keys(y||{})]);for(const k of keys)walk(x?.[k],y?.[k],path?`${path}.${k}`:k);return;
      }
      const secret=/password|secret|ospfkey/i.test(path);
      const show=(v:any)=>secret?(v?'••••':'—'):v===undefined?'—':JSON.stringify(v);
      changes.push({field:path,before:show(x),after:show(y)});
    };walk(a,b,'');return changes;
  };
  const inspectVersion=async(revision:number,restore=false)=>{
    if(!history||!start())return;
    const site=history.site;setListError('');if(restore)setLoadingForm(true);
    try{
      const [{data:old},{data:latest}]=await Promise.all([api.get<{draft:Draft}>(`/object-constructor/sites/${site.id}/versions/${revision}`),api.get<Site & {draft:Draft}>(`/object-constructor/sites/${site.id}`)]);
      if(!restore){setComparison({revision,changes:compareDrafts(old.draft,latest.draft)});return;}
      if(!canSwitch()||!window.confirm(`Восстановить версию ${revision} объекта «${site.name}» как новую версию?`))return;
      setLoadingForm(true);
      const {data}=await api.put<Site>(`/object-constructor/sites/${site.id}`,{revision:latest.revision,draft:old.draft});
      loadDraft(old.draft);setCurrent(data);pendingId.current='';setSavedKey(canonical({...old.draft,bridgeLan:{...defaultBridge(),...old.draft.bridgeLan},loopbackAddress:old.draft.loopbackAddress||'',services:old.draft.services||defaultServices()}));setSaveError('');setMessage('Версия восстановлена');setHistory(null);setComparison(null);await refreshSites();
    }catch(e){setListError(explain(e));}finally{finish();}
  };
  const effectiveRouterId=ospfRouterId || (l2tp.some(t=>t.enabled)?loopbackIP(loopbackAddress):'');
  const errors = useMemo(() => {
    const out: string[] = [];
    if (!name.trim()) out.push('Укажите название объекта.');
    const ids = vlans.map(v => v.id.trim()).filter(Boolean);
    if (new Set(ids).size !== ids.length) out.push('VLAN ID должны быть уникальными.');
    vlans.forEach((v, i) => {
      if (!/^\d+$/.test(v.id) || Number(v.id) < 1 || Number(v.id) > 4094) out.push(`VLAN №${i + 1}: ID должен быть от 1 до 4094.`);
      if (v.subnet && !validCidr(v.subnet)) out.push(`VLAN ${v.id}: укажите подсеть в формате CIDR, например 192.168.60.0/24.`);
      if (v.gateway && !validIp(v.gateway)) out.push(`VLAN ${v.id}: некорректный IP шлюза.`);
      if (v.dhcp && (!validIp(v.poolStart) || !validIp(v.poolEnd))) out.push(`VLAN ${v.id}: заполните корректные границы DHCP-пула.`);
    });
    if (wanMode === 'static' && (!validCidr(wanAddress) || !validIp(wanGateway))) out.push('Для статического WAN укажите адрес с маской и шлюз.');
    if (wanMode === 'pppoe' && (!pppoeUser.trim() || !pppoePassword)) out.push('Для PPPoE укажите логин и пароль.');
    if (ospfRouterId && !validIp(ospfRouterId)) out.push('OSPF Router ID должен быть IPv4-адресом.');
    return out;
  }, [name, vlans, wanMode, wanAddress, wanGateway, pppoeUser, pppoePassword, ospfRouterId]);

  const networkKey = JSON.stringify({ bridgeLan,wanAddress:wanMode==='static'?wanAddress:'',ports, vlans, dns, wanPort, model,splitDns:services.splitDns,guestIds:guests.split(',').map(x=>x.trim()).filter(x=>/^\d+$/.test(x)&&Number(x)>=1&&Number(x)<=4094).map(Number),wifiVlans:wifiEnabled&&services.wifiMode==='local'&&model==='hAP ax²'?[services.corpWifi,services.guestWifi].filter(w=>w.enabled&&/^\d+$/.test(w.vlan)).map(w=>Number(w.vlan)):[] });
  const [network, setNetwork] = useState<{key: string; errors: string[]; config: string} | null>(null);
  const networkResult = network?.key === networkKey ? network : null;
  useEffect(() => {
    let active = true;
    const timer = setTimeout(() => {
      api.post('/object-constructor/generate-network', JSON.parse(networkKey)).then(({data}) => {
        if (active) setNetwork({key: networkKey, ...data});
      }).catch(() => {
        if (active) setNetwork({key: networkKey, errors: ['Backend: не удалось проверить сеть.'], config: ''});
      });
    }, 350);
    return () => { active = false; clearTimeout(timer); };
  }, [networkKey]);
  const routing = useMemo(() => buildRouting({bridge:bridgeNet,wanMode, wanPort, vlans, ports, tunnels:l2tp, routerId:effectiveRouterId, loopbackAddress, wanAddress, area:ospfArea, profile:firewallProfile, management, guests, corporate}), [bridgeLan,wanMode, wanPort, vlans, ports, l2tp, effectiveRouterId, loopbackAddress, wanAddress, ospfArea, firewallProfile, management, guests, corporate]);
  const extra=buildServices(services,{wifiEnabled,model,vlans,ports,guests,firewallProfile});
  const dnsResult=buildDns(services,dns,vlans,guests,firewallProfile,l2tp,bridgeNet);
  const allErrors = [...(bridgeLan.enabled&&!bridgeNet?['Bridge: укажите корректный IPv4/CIDR.']:[]),...errors, ...routing.errors,...extra.errors,...dnsResult.errors,...(saveError.startsWith('Loopback уже')?['Loopback уже назначен другому объекту.']:[]), ...(networkResult?.errors || ['Проверка сетевой части…'])];
  const config = useMemo(() => {
    const lines = [
      '# ROSzetta — предварительная конфигурация RouterOS 7',
      `# Объект: ${safeName(name)}`,
      `# Профиль: ${profileLabel(profile)}; модель: ${model}`,
      '# ВНИМАНИЕ: проверьте порты, адресацию и секреты перед применением.',
      '',
      `/system identity set name=${rosQuote(identity || name || 'new-object')}`,
      '',
      networkResult?.config || '# Сетевая часть не проверена',
    ];
    lines.push('', '# --- WAN ---');
    if (wanMode === 'pppoe') {
      lines.push(`/interface pppoe-client add name=pppoe-out1 interface=${wanPort} user=${rosQuote(pppoeUser)} password=${rosQuote(pppoePassword)} add-default-route=yes use-peer-dns=no disabled=no`);
    } else if (wanMode === 'dhcp') {
      lines.push(`/ip dhcp-client add interface=${wanPort} add-default-route=yes use-peer-dns=no disabled=no`);
    } else {
      lines.push(`/ip address add address=${wanAddress} interface=${wanPort} comment="WAN static"`);
      lines.push(`/ip route add dst-address=0.0.0.0/0 gateway=${wanGateway}`);
    }
    lines.push('', dnsResult.config || '# DNS: исправьте ошибки');
    let routingConfig=routing.config;
    if(extra.inputRules.length) routingConfig=routingConfig.replace('/ip firewall filter add chain=input action=drop in-interface-list=GUEST', ['/ip firewall filter add chain=input action=drop in-interface-list=GUEST',...extra.inputRules].join('\n'));
    if(dnsResult.inputRules.length) routingConfig=routingConfig.replace('/ip firewall filter add chain=input action=drop in-interface-list=GUEST', ['/ip firewall filter add chain=input action=drop in-interface-list=GUEST',...dnsResult.inputRules].join('\n'));
    lines.push('', routingConfig || '# Firewall / VPN: исправьте ошибки');
    const hardening=routing.errors.length?'':buildHardening(firewallProfile,management);
    lines.push('',hardening);
    lines.push('',hardening?dnsResult.enableConfig.split('\n').filter(x=>!x.startsWith('/ipv6 firewall filter ')).join('\n'):dnsResult.enableConfig);
    lines.push('',extra.config || (extra.errors.length?'# Wi-Fi / службы: исправьте ошибки':''));
    lines.push('', '# --- Завершение ---', '# Сгенерировано ROSzetta Object Constructor');
    return lines.join('\n');
  }, [name, profile, model, identity, ports, wanMode, wanPort, pppoeUser, pppoePassword, wanAddress, wanGateway, vlans, dns, l2tp, ospfRouterId, ospfArea, firewallProfile, management, wifiEnabled, wifiSsid, networkResult, routing, extra.config, extra.inputRules.join("\n"),dnsResult.config,dnsResult.enableConfig,dnsResult.inputRules.join("\n")]);

  const members=(v:string)=>v.split(',').map(x=>x.trim()).filter(Boolean);
  const updatePort = (index: number, patch: Partial<Port>) => {
    const old=ports[index],next={...old,...patch};
    setPorts(ps=>ps.map((p,i)=>i===index?next:p));
    // Do not discard other memberships; remove only those incompatible with the new role/PVID.
    setVlans(vs=>vs.map(v=>{
      const tagged=members(v.tagged), untagged=members(v.untagged);
      const native=(next.role==='lan'||next.role==='hybrid')&&Number(next.pvid)===Number(v.id)&&!!next.pvid;
      const mayTag=next.role==='trunk'||(next.role==='hybrid'&&!native);
      return {...v,tagged:[...tagged.filter(x=>x!==old.name),...(mayTag&&tagged.includes(old.name)?[next.name]:[])].join(','),untagged:[...untagged.filter(x=>x!==old.name),...(native?[next.name]:[])].join(',')};
    }));
  };
  const assignUntagged=(index:number,value:string)=>{
    const target=vlans[index],selected=members(value),previous=members(target.untagged);
    const added=selected.filter(x=>!previous.includes(x)),removed=previous.filter(x=>!selected.includes(x));
    setPorts(ps=>ps.map(p=>added.includes(p.name)?{...p,pvid:target.id}:removed.includes(p.name)&&Number(p.pvid)===Number(target.id)?{...p,pvid:''}:p));
    setVlans(vs=>vs.map((v,i)=>({...v,untagged:i===index?value:members(v.untagged).filter(x=>!added.includes(x)).join(','),tagged:i===index?members(v.tagged).filter(x=>!selected.includes(x)).join(','):v.tagged})));
  };
  const updateVlan = (index: number, patch: Partial<Vlan>) => {
    if(patch.id!==undefined&&patch.id!==vlans[index].id){const v=vlans[index];setPorts(old=>old.map(p=>members(v.untagged).includes(p.name)&&(p.role==='lan'||p.role==='hybrid')?{...p,pvid:patch.id!}:p));}
    setVlans(old=>old.map((v,i)=>i===index?{...v,...patch}:v));
  };
  const download = () => {
    if (allErrors.length) return;
    const blob = new Blob([config], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `${safeName(name)}.rsc`; a.click(); URL.revokeObjectURL(url);
  };



  return <div className="space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-2"><div><h3 className="font-semibold">Конструктор объектов</h3><p className="text-xs text-mk-mute">Подготовка конфигураций MikroTik RouterOS 7</p></div><span className="text-xs rounded bg-mk-panel2 px-2 py-1 text-mk-mute">Генератор v0.9 · IP на Bridge</span></div>
    <div className={cardClass}>
      <div className="flex flex-wrap items-center gap-2"><b className="text-sm">Сохранённые объекты</b><button className="btn-secondary" disabled={busy} onClick={reset}>Новый объект</button><button className="btn-primary" disabled={busy} onClick={()=>void save()}>Сохранить черновик</button><label className="flex gap-2 items-center text-xs"><input type="checkbox" checked={autoSave} onChange={e=>setAutoSave(e.target.checked)}/> Автосохранение</label></div>
      <p className="text-xs text-mk-mute">{current?`Открыт: ${current.name}`:'Новый объект'} · {busy?'Выполняется запрос…':dirty?'Есть несохранённые изменения':message||'Нет изменений'}. Автосохранение через 1,2 с после ввода. Для сохранения и открытия нужен разблокированный Vault.</p>
      {window.location.protocol!=='https:'&&<p className="text-xs text-mk-warn">Для реальных паролей используйте HTTPS или защищённый SSH-туннель. Сейчас страница открыта по HTTP.</p>}
      {saveError&&<p role="alert" className="text-xs text-red-500">{saveError} Нажмите «Сохранить черновик» для повтора. {saveError.startsWith('Объект изменён')&&<button type="button" className="btn-secondary" disabled={busy} onClick={detachDraft}>Сохранить как новый черновик</button>}</p>}
      {listError&&<p role="alert" className="text-xs text-red-500">{listError}</p>}
      <div className="flex gap-2"><input className={inputClass} value={search} onChange={e=>setSearch(e.target.value)} placeholder="Поиск по названию, профилю, модели"/><button className="btn-secondary" disabled={busy} onClick={()=>void refreshSites()}>Обновить</button></div>
      {sites.filter(x=>`${x.name} ${x.model} ${x.profile} ${profileLabel(x.profile)}`.toLocaleLowerCase().includes(search.toLocaleLowerCase())).map(site=><div className="flex flex-wrap items-center gap-2 border-t border-mk-border pt-2" key={site.id}><div className="flex-1"><b className="text-sm">{site.name}</b><p className="text-xs text-mk-mute">{site.model} · {profileLabel(site.profile)} · {new Date(site.updated_at).toLocaleString()}</p></div><button className="btn-secondary" disabled={busy} onClick={()=>void openSite(site)}>Открыть</button><button className="btn-secondary" disabled={busy} onClick={()=>void openSite(site,true)}>Дублировать</button><button className="btn-secondary" disabled={busy} onClick={()=>void showHistory(site)}>История</button><button className="btn-secondary" disabled={busy} onClick={()=>void removeSite(site)}>Удалить</button></div>)}
      {history&&<div className="border border-mk-border rounded p-3 space-y-2"><div className="flex justify-between"><b>История: {history.site.name}</b><button className="btn-secondary" disabled={busy} onClick={()=>{setHistory(null);setComparison(null)}}>Закрыть</button></div>{history.versions.map(v=><div key={v.revision} className="flex flex-wrap gap-2 items-center"><span className="flex-1">Версия {v.revision} · {new Date(v.updated_at).toLocaleString()}</span><button className="btn-secondary" disabled={busy} onClick={()=>void inspectVersion(v.revision)}>Сравнить с текущей</button><button className="btn-secondary" disabled={busy} onClick={()=>void inspectVersion(v.revision,true)}>Восстановить</button></div>)}{comparison&&<div className="overflow-auto max-h-80"><p>Версия {comparison.revision} → текущая (секреты скрыты)</p>{!comparison.changes.length?<p>Нет различий</p>:<table className="w-full text-xs"><thead><tr><th>Поле</th><th>Было</th><th>Стало</th></tr></thead><tbody>{comparison.changes.map(c=><tr key={c.field}><td>{c.field}</td><td className="break-all">{c.before}</td><td className="break-all">{c.after}</td></tr>)}</tbody></table>}</div>}</div>}
      <p className="text-xs text-mk-mute">Чтобы экспортировать сохранённый объект, откройте его и нажмите «Скачать .rsc» после проверки. Секреты и Loopback копии очищаются. Объекты доступны только создавшему их пользователю.</p>
    </div>
    <fieldset disabled={loadingForm} className="space-y-3 min-w-0 border-0 p-0">
    <div className={cardClass}>
      <div className="flex items-center gap-2"><Network size={16}/><b className="text-sm">1. Объект и оборудование</b></div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Field label="Название объекта" value={name} invalid={!name.trim()} onChange={setName} placeholder="Например, Склад Москва" />
        <label><span className={labelClass}>Профиль объекта</span><select className={inputClass} value={profile} onChange={e=>{setProfile(e.target.value);setProfileIds({});setProfileError('')}}>{profiles.map(p=><option key={p.id} value={p.id}>{p.label}</option>)}</select></label>
        <details className="md:col-span-3 border border-mk-border rounded p-2"><summary className="cursor-pointer text-sm">Сравнение профилей и добавление типовых VLAN</summary><div className="overflow-x-auto mt-2"><table className="w-full text-xs text-left"><thead><tr><th>Сеть</th>{profiles.map(p=><th key={p.id}>{p.label}</th>)}</tr></thead><tbody>{networkRoles.map(r=><tr key={r.name}><td>{r.label}</td>{profiles.map(p=><td key={p.id}>{recommendedRoles(p.id).some(x=>x.name===r.name)?'Да':'Опционально'}</td>)}</tr>)}<tr><td>L2TP, OSPF, Firewall, DNS, NTP, SNMP</td>{profiles.map(p=><td key={p.id}>Доступны</td>)}</tr></tbody></table></div><p className="text-xs text-mk-mute mt-2">Введите ID нужных новых VLAN. Пустые поля пропускаются. Уже созданные сети не изменяются. Адреса, порты, Wi-Fi и туннели настройте отдельно.</p><div className="grid grid-cols-2 md:grid-cols-3 gap-2 mt-2">{recommendedRoles(profile).filter(r=>!vlans.some(v=>v.name.toLowerCase()===r.name)).map(r=><Field key={r.name} label={r.label+' — VLAN ID'} value={profileIds[r.name]||''} onChange={v=>setProfileIds(old=>({...old,[r.name]:v}))}/>)}</div><button type="button" className="btn-secondary mt-2" onClick={()=>{try{const additions=planProfile(profile,vlans,profileIds);setVlans(old=>[...old,...additions.map(v=>({...defaultVlan(),...v}))]);const guest=additions.find(v=>v.name==='guest');if(guest)setGuests(old=>[...new Set([...old.split(',').map(x=>x.trim()).filter(Boolean),guest.id])].join(','));setProfileIds({});setProfileError(additions.length?'Добавлено VLAN: '+additions.length:'Нет новых VLAN для добавления');}catch(e){setProfileError(e instanceof Error?e.message:'Проверьте VLAN ID');}}}>Добавить выбранные VLAN</button>{profileError&&<p role="status" className="text-xs mt-1">{profileError}</p>}</details>
        <label><span className={labelClass}>Модель MikroTik</span><select className={inputClass} value={model} onChange={e => setModel(e.target.value)}><option>hAP ax²</option><option>RB5009</option><option>Другая RouterOS 7</option></select></label>
        <Field label="System Identity" value={identity} onChange={setIdentity} placeholder="Если отличается от названия" />
        <Field label="Loopback (lo), IPv4 /32" value={loopbackAddress} onChange={setLoopbackAddress} placeholder="10.0.0.50/32" invalid={!!loopbackAddress&&!loopbackIP(loopbackAddress)} />
        <p className="text-xs text-mk-mute self-end">При включённом OSPF адрес lo анонсируется как passive. Пустой Router ID берётся из lo при включённом туннеле.</p>
      </div>
    </div>
    <div className={cardClass}>
      <div className="flex items-center gap-2"><Cable size={16}/><b className="text-sm">2. Провайдер и WAN</b></div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <label><span className={labelClass}>Тип подключения</span><select className={inputClass} value={wanMode} onChange={e => setWanMode(e.target.value as WanMode)}><option value="pppoe">PPPoE</option><option value="static">Статический IP</option><option value="dhcp">DHCP Client</option></select></label>
        <Field label="WAN-порт" value={wanPort} onChange={setWanPort} placeholder="ether1" />
        {wanMode === 'pppoe' && <><Field label="Логин PPPoE" value={pppoeUser} onChange={setPppoeUser}/><Field label="Пароль PPPoE" value={pppoePassword} onChange={setPppoePassword} type="password"/></>}
        {wanMode === 'static' && <><Field label="WAN IP с маской" value={wanAddress} onChange={setWanAddress} placeholder="203.0.113.2/30"/><Field label="Шлюз провайдера" value={wanGateway} onChange={setWanGateway} placeholder="203.0.113.1"/></>}
      </div>
    </div>
    <div className={cardClass}>
      <div className="flex items-center gap-2"><Cable size={16}/><b className="text-sm">3. Физические порты и Bridge</b></div>
      <p className="text-xs text-mk-mute">Назначение портов задаётся вручную. Сверьте имена интерфейсов с конкретной моделью.</p>
      <div className="space-y-2">{ports.map((p, i) => <div key={i} className="grid grid-cols-3 gap-2 items-end"><Field label="Интерфейс" value={p.name} onChange={v => updatePort(i, { name: v })}/><label><span className={labelClass}>Назначение</span><select className={inputClass} value={p.role} onChange={e => updatePort(i, { role: e.target.value as Port['role'] })}><option value="wan">WAN</option><option value="lan">LAN access</option><option value="trunk">Trunk</option><option value="hybrid">Hybrid</option><option value="unused">Не используется</option></select></label><div className="flex gap-1"><Field label="PVID" value={p.pvid} onChange={v => updatePort(i, { pvid: v })}/><button className="btn-secondary self-end" title="Удалить порт" onClick={() => {setPorts(old => old.filter((_, n) => n !== i));setVlans(old=>old.map(v=>({...v,tagged:members(v.tagged).filter(x=>x!==p.name).join(','),untagged:members(v.untagged).filter(x=>x!==p.name).join(',')})))}}><Trash2 size={14}/></button></div></div>)}</div>
      <button className="btn-secondary" onClick={() => setPorts(old => [...old, { name: `ether${old.length + 1}`, role: 'lan', pvid: '1' }])}><Plus size={14}/> Добавить порт</button>
      <div className="rounded border border-mk-border p-3 space-y-2">
        <label className="flex gap-2 items-center text-sm"><input type="checkbox" checked={bridgeLan.enabled} onChange={e=>patchBridge({enabled:e.target.checked})}/> Назначить IP-адрес на bridge-lan</label>
        {bridgeLan.enabled&&<>
          <div className="grid grid-cols-2 gap-2"><Field label="IPv4 / CIDR" value={bridgeLan.address} placeholder="10.180.10.1/23" invalid={!bridgeNet} onChange={address=>patchBridge({address})}/><Field label="PVID Bridge (native VLAN)" value={bridgeLan.pvid} onChange={pvid=>patchBridge({pvid})}/></div>
          <p className="text-xs text-mk-mute">PVID Bridge не должен совпадать с отдельным VLAN. Назначьте этот PVID нужным Access или Hybrid портам. На Hybrid остальные VLAN передаются с тегами.</p>
          <fieldset className="rounded border border-mk-border p-2"><legend className={labelClass}>Untagged Bridge (Access / Hybrid)</legend>{ports.map((p,i)=>(p.role==='lan'||p.role==='hybrid')&&<label key={i} className="flex gap-2 items-center text-xs py-1"><input type="checkbox" disabled={!/^\d{1,4}$/.test(bridgeLan.pvid)||Number(bridgeLan.pvid)<1||Number(bridgeLan.pvid)>4094||vlans.some(v=>Number(v.id)===Number(bridgeLan.pvid))} checked={!!p.pvid&&Number(p.pvid)===Number(bridgeLan.pvid)} onChange={e=>updatePort(i,{pvid:e.target.checked?bridgeLan.pvid:''})}/>{p.name}</label>)}</fieldset>
          <label className="flex gap-2 items-center text-xs"><input type="checkbox" checked={bridgeLan.dhcp} onChange={e=>patchBridge({dhcp:e.target.checked})}/> DHCP на Bridge</label>
          {bridgeLan.dhcp&&<div className="grid grid-cols-2 md:grid-cols-3 gap-2"><Field label="Начало пула Bridge" value={bridgeLan.poolStart} onChange={poolStart=>patchBridge({poolStart})}/><Field label="Конец пула Bridge" value={bridgeLan.poolEnd} onChange={poolEnd=>patchBridge({poolEnd})}/><button type="button" className="btn-secondary self-end" disabled={!bridgeNet||!suggestPool(bridgeNet.subnet,bridgeNet.gateway)} onClick={()=>{if(bridgeNet){const p=suggestPool(bridgeNet.subnet,bridgeNet.gateway);if(p)patchBridge(p)}}}>Рассчитать пул</button></div>}
          <label className="flex gap-2 items-center text-xs"><input type="checkbox" checked={bridgeLan.ospf} onChange={e=>patchBridge({ospf:e.target.checked})}/> Анонсировать Bridge в OSPF (Passive)</label>
          <p className="text-xs text-mk-mute">Bridge включается в доверенный LAN корпоративного Firewall. При Split DNS DHCP выдаёт адрес Bridge как DNS.</p>
        </>}
      </div>
    </div>
    <div className={cardClass}>
      <div className="flex items-center justify-between"><div className="flex items-center gap-2"><Network size={16}/><b className="text-sm">4. VLAN и DHCP</b></div><button className="btn-secondary" onClick={() => setVlans(old => [...old, { ...defaultVlan(), id: String(Math.max(0, ...old.map(v => Number(v.id) || 0)) + 1), name: 'new-vlan' }])}><Plus size={14}/> Добавить VLAN</button></div>
      <p className="text-xs text-mk-mute">VLAN 60 — стандартная сеть видеонаблюдения. VLAN 10 и 160 в шаблон не включены. Остальные сети добавляются индивидуально.</p>
      {vlans.map((v, i) => <div key={i} className="rounded border border-mk-border p-3 space-y-2"><div className="flex justify-between items-center"><b className="text-sm">VLAN #{i + 1}</b><button className="text-mk-err" onClick={() => setVlans(old => old.filter((_, n) => n !== i))}><Trash2 size={14}/></button></div><div className="grid grid-cols-2 md:grid-cols-4 gap-2"><Field label="VLAN ID" value={v.id} onChange={x => updateVlan(i, { id: x })}/><Field label="Имя" value={v.name} onChange={x => updateVlan(i, { name: x })}/><Field label="Подсеть CIDR" value={v.subnet} invalid={!validCidr(v.subnet)} onChange={x => updateVlan(i, { subnet: x })} placeholder="192.168.60.0/24"/><Field label="IP шлюза" value={v.gateway} invalid={!validIp(v.gateway)} onChange={x => updateVlan(i, { gateway: x })} placeholder="192.168.60.1"/></div><label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={v.dhcp} onChange={e => updateVlan(i, { dhcp: e.target.checked })}/> Включить DHCP</label>{v.dhcp && <div className="grid grid-cols-2 md:grid-cols-4 gap-2"><Field label="Начало пула" value={v.poolStart} invalid={!validIp(v.poolStart)} onChange={x => updateVlan(i, { poolStart: x })}/><Field label="Конец пула" value={v.poolEnd} invalid={!validIp(v.poolEnd)} onChange={x => updateVlan(i, { poolEnd: x })}/><button type="button" className="btn-secondary self-end" disabled={!suggestPool(v.subnet,v.gateway)} onClick={()=>{const pool=suggestPool(v.subnet,v.gateway);if(pool)updateVlan(i,pool)}}>Рассчитать пул</button></div>}<div className="grid grid-cols-2 gap-2"><PortPicker label="Tagged (Trunk / Hybrid)" value={v.tagged} options={ports.filter(p=>p.role==='trunk'||(p.role==='hybrid'&&Number(p.pvid)!==Number(v.id))).map(p=>p.name)} onChange={x=>updateVlan(i,{tagged:x})}/><PortPicker label="Untagged (Access / Hybrid)" value={v.untagged} options={ports.filter(p=>p.role==='lan'||p.role==='hybrid').map(p=>p.name)} onChange={x=>assignUntagged(i,x)}/></div></div>)}
      <p className="text-xs text-mk-mute">DNS для DHCP и маршрутизатора задаются в разделе 8 «Корпоративные службы».</p>
    </div>
    <div className={cardClass}>
      <div className="flex items-center gap-2"><Route size={16}/><b className="text-sm">5. L2TP и OSPF</b></div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">{l2tp.map((t, i) => <div className="rounded border border-mk-border p-3 space-y-2" key={i}><label className="flex items-center gap-2 text-sm font-semibold"><input type="checkbox" checked={t.enabled} onChange={e=>setL2tp(old=>old.map((x,n)=>n===i?{...x,enabled:e.target.checked}:x))}/>{i === 0 ? 'Основной туннель' : 'Резервный туннель'}</label>{t.enabled && <><Field label="Имя интерфейса" value={t.name} onChange={v => setL2tp(old => old.map((x, n) => n === i ? { ...x, name: v } : x))}/><Field label="Адрес сервера" value={t.server} invalid={!t.server.trim()} onChange={v => setL2tp(old => old.map((x, n) => n === i ? { ...x, server: v } : x))}/><Field label="Логин" value={t.user} invalid={!t.user.trim()} onChange={v => setL2tp(old => old.map((x, n) => n === i ? { ...x, user: v } : x))}/><Field label="Пароль" value={t.password} invalid={!t.password} type="password" onChange={v => setL2tp(old => old.map((x, n) => n === i ? { ...x, password: v } : x))}/><Field label="IPsec PSK (необязательно)" value={t.ipsecSecret} type="password" onChange={v => setL2tp(old => old.map((x, n) => n === i ? { ...x, ipsecSecret: v } : x))}/><Field label="OSPF MD5 ключ (необязательно)" value={t.ospfKey} invalid={!!effectiveRouterId&&!!t.ospfKey&&new TextEncoder().encode(t.ospfKey).length>16} type="password" onChange={v => setL2tp(old => old.map((x, n) => n === i ? { ...x, ospfKey: v } : x))}/><Field label="OSPF Cost" value={t.cost} onChange={v => setL2tp(old => old.map((x, n) => n === i ? { ...x, cost: v } : x))}/></>}</div>)}</div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3"><Field label="OSPF Router ID" value={ospfRouterId} onChange={setOspfRouterId} placeholder={loopbackIP(loopbackAddress)||"10.0.0.1"}/><Field label="OSPF Area" value={ospfArea} onChange={setOspfArea} placeholder="backbone"/></div>
    </div>
    <div className={cardClass}>
      <div className="flex items-center gap-2"><Shield size={16}/><b className="text-sm">6. Типовой Firewall</b></div>
      <label><span className={labelClass}>Профиль Firewall</span><select className={inputClass} value={firewallProfile} onChange={e => setFirewallProfile(e.target.value)}><option value="standard">Корпоративный типовой (базовый)</option><option value="strict">Строгий — минимально разрешённый доступ</option><option value="custom">Без шаблона — ручная настройка позже</option></select></label>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3"><Field label="Адреса управления (IP/CIDR через запятую)" value={management} onChange={setManagement} placeholder="10.110.0.30/32"/><Field label="Гостевые VLAN ID (через запятую)" value={guests} onChange={setGuests} placeholder="140"/><Field label="Дополнительные корпоративные сети (CIDR)" value={corporate} onChange={setCorporate}/></div>
      <p className="text-xs text-mk-warn">Адаптированный IPv4 шаблон: доступ к управлению только из LAN/VPN по разрешённым IP; гостевые VLAN изолированы. IPv6-транзит блокируется; управление только по разрешённым IPv4. Без индивидуальных правил. Только тестовый экспорт для чистой конфигурации.</p>
    </div>
    <div className={cardClass}>
      <div className="flex items-center gap-2"><Wifi size={16}/><b className="text-sm">7. Wi-Fi (опционально)</b></div>
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={wifiEnabled} onChange={e => setWifiEnabled(e.target.checked)}/> Настраивать Wi-Fi на этом устройстве</label>
      {wifiEnabled && <div className="space-y-3">
        <label><span className={labelClass}>Режим (RouterOS 7.13+, wifi-qcom AX)</span><select className={inputClass} value={services.wifiMode} onChange={e=>patchServices({wifiMode:e.target.value})}><option value="local">Локальные радиоинтерфейсы</option><option value="capsman">CAPsMAN AX (внешние CAP)</option></select></label>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3"><Field label="Страна (точное имя RouterOS)" value={services.country} onChange={country=>patchServices({country})} placeholder="Russia"/><Field label="Мощность dBm (пусто — авто)" value={services.txPower} onChange={txPower=>patchServices({txPower})}/></div>
        {services.wifiMode==='local'?<div className="grid grid-cols-2 gap-3"><Field label="Радио 2,4 ГГц" value={services.radio24} onChange={radio24=>patchServices({radio24})}/><Field label="Радио 5 ГГц" value={services.radio5} onChange={radio5=>patchServices({radio5})}/></div>:<div className="grid grid-cols-2 gap-3"><Field label="VLAN управления CAP" value={services.capVlan} onChange={capVlan=>patchServices({capVlan})}/><Field label="Разрешённый IPv4 CAP" value={services.capAddress} onChange={capAddress=>patchServices({capAddress})}/></div>}
        {(['corpWifi','guestWifi'] as const).map(key=>{const w=services[key];return <div key={key} className="rounded border border-mk-border p-3 space-y-3"><label className="flex items-center gap-2"><input type="checkbox" checked={w.enabled} onChange={e=>patchWifi(key,{enabled:e.target.checked})}/>{key==='corpWifi'?'Корпоративный Wi-Fi':'Гостевой Wi-Fi'}</label>{w.enabled&&<><div className="grid grid-cols-1 md:grid-cols-2 gap-3"><Field label="SSID" value={w.ssid} onChange={ssid=>patchWifi(key,{ssid})}/><label><span className={labelClass}>VLAN</span><select className={inputClass} value={w.vlan} onChange={e=>patchWifi(key,{vlan:e.target.value})}><option value="">Выберите VLAN</option>{vlans.map((v,i)=><option key={i} value={String(Number(v.id))}>{v.id} — {v.name}</option>)}</select></label><label><span className={labelClass}>Авторизация</span><select className={inputClass} value={w.auth} onChange={e=>patchWifi(key,{auth:e.target.value})}>{['wpa2-psk','wpa3-psk','wpa2-wpa3-psk','wpa2-eap','wpa3-eap'].map(a=><option key={a}>{a}</option>)}</select></label>{w.auth.includes('psk')&&<Field label="PSK" type="password" value={w.password} onChange={password=>patchWifi(key,{password})}/>}</div><div className="flex flex-wrap gap-4">{(['band24','band5','isolate'] as const).map((k,i)=><label key={k} className="flex gap-2 text-sm"><input type="checkbox" checked={w[k]} onChange={e=>patchWifi(key,{[k]:e.target.checked})}/>{['2,4 ГГц','5 ГГц','Изоляция клиентов'][i]}</label>)}</div></>}</div>})}
        {[services.corpWifi,services.guestWifi].some(w=>w.enabled&&w.auth.includes('eap'))&&<div className="grid grid-cols-2 gap-3"><Field label="RADIUS IPv4" value={services.radiusAddress} onChange={radiusAddress=>patchServices({radiusAddress})}/><Field label="RADIUS shared secret" type="password" value={services.radiusSecret} onChange={radiusSecret=>patchServices({radiusSecret})}/></div>}
        <p className="text-xs text-mk-warn">Проверьте реальные имена и диапазоны радио. CAPsMAN: внешний AX CAP требует отдельной настройки bridge, VLAN и trunk. Старые wifi-qcom-ac / wireless не поддерживаются. Изоляция клиентов действует на одном Wi-Fi интерфейсе; межрадиоклиентская L2-изоляция отдельно. При EAP проверьте политику VLAN на RADIUS.</p>
      </div>}
    </div>
    <div className={cardClass}><b className="text-sm">8. Корпоративные службы</b>
      <Field label="Часовой пояс (IANA TZ)" value={services.timezone} onChange={timezone=>patchServices({timezone})} placeholder="Europe/Moscow"/>
      <label className="flex gap-2"><input type="checkbox" checked={services.ntpEnabled} onChange={e=>patchServices({ntpEnabled:e.target.checked})}/> NTP-клиент</label>{services.ntpEnabled&&<Field label="NTP-серверы (через запятую)" value={services.ntpServers} onChange={ntpServers=>patchServices({ntpServers})}/>}
      <label className="flex gap-2"><input type="checkbox" checked={services.snmpEnabled} onChange={e=>patchServices({snmpEnabled:e.target.checked})}/> SNMPv3 (SHA1/AES, только чтение)</label>{services.snmpEnabled&&<div className="grid grid-cols-1 md:grid-cols-2 gap-3"><Field label="Пользователь SNMPv3" value={services.snmpUser} onChange={snmpUser=>patchServices({snmpUser})}/><Field label="Разрешённые адреса мониторинга IP/CIDR" value={services.snmpAddress} onChange={snmpAddress=>patchServices({snmpAddress})}/><Field label="Пароль аутентификации" type="password" value={services.snmpAuthPassword} onChange={snmpAuthPassword=>patchServices({snmpAuthPassword})}/><Field label="Пароль шифрования" type="password" value={services.snmpEncryptionPassword} onChange={snmpEncryptionPassword=>patchServices({snmpEncryptionPassword})}/></div>}
      <Field label="Публичные DNS IPv4 (через запятую)" value={dns} onChange={setDns}/>
      <label className="flex gap-2"><input type="checkbox" checked={services.splitDns} onChange={e=>patchServices({splitDns:e.target.checked})}/> Split DNS (RouterOS с DNS Forwarders)</label>
      {services.splitDns&&<div className="space-y-3"><p className="text-xs text-mk-mute">DHCP доверенных VLAN и Bridge выдаёт шлюз как DNS. Гости используют публичные DNS. Требуется IPv4 Firewall-шаблон.</p><div className="grid grid-cols-2 gap-3"><Field label="Корпоративный домен" value={services.dnsDomain} onChange={dnsDomain=>patchServices({dnsDomain})}/><Field label="Корпоративные DNS" value={services.dnsCorporate} onChange={dnsCorporate=>patchServices({dnsCorporate})}/></div><label className="flex gap-2"><input type="checkbox" checked={services.dnsSubdomains} onChange={e=>patchServices({dnsSubdomains:e.target.checked})}/> Включая поддомены</label><div className="text-sm font-semibold">Публичные исключения (точные имена)</div>{services.dnsExceptions.map((r,i)=><div key={i} className="grid grid-cols-[1fr_1fr_auto] gap-2 items-end"><Field label="Домен" value={r.domain} onChange={domain=>patchServices({dnsExceptions:services.dnsExceptions.map((x,j)=>j===i?{...x,domain}:x)})}/><Field label="DNS-серверы" value={r.servers} onChange={servers=>patchServices({dnsExceptions:services.dnsExceptions.map((x,j)=>j===i?{...x,servers}:x)})}/><button type="button" onClick={()=>patchServices({dnsExceptions:services.dnsExceptions.filter((_,j)=>j!==i)})}><Trash2 size={16}/></button></div>)}<button type="button" disabled={services.dnsExceptions.length>=64} onClick={()=>patchServices({dnsExceptions:[...services.dnsExceptions,{domain:'',servers:''}]})}>+ Добавить исключение</button></div>}

    </div>
    {l2tp.filter(t=>t.enabled&&!t.ipsecSecret).map(t=><p key={t.name} className="text-xs text-mk-warn">{t.name}: IPsec отключён; шифрование IPsec отсутствует.</p>)}
    {effectiveRouterId&&l2tp.filter(t=>t.enabled&&!t.ospfKey).map(t=><p key={t.name} className="text-xs text-mk-warn">{t.name}: OSPF без аутентификации.</p>)}
    {l2tp.every(t=>t.enabled)&&!!l2tp[0].server&&l2tp[0].server.trim().toLowerCase()===l2tp[1].server.trim().toLowerCase()&&<p className="text-xs text-mk-warn">Оба туннеля используют один сервер; отказ шлюза затронет оба туннеля.</p>}
    <ObjectPreflight key={JSON.stringify([model,ports,services.splitDns,wifiEnabled,services.wifiMode])} model={model} ports={ports} splitDns={services.splitDns} wifiEnabled={wifiEnabled} wifiMode={services.wifiMode} config={config} valid={allErrors.length===0}/>
    {allErrors.length > 0 && <div className="rounded border border-mk-warn/40 bg-mk-warn/5 p-3"><div className="flex gap-2 items-center text-sm font-medium text-mk-warn"><AlertTriangle size={15}/> Требуется заполнить или исправить</div><ul className="mt-2 list-disc pl-5 text-xs space-y-1">{allErrors.map((e, i) => <li key={i}>{e}</li>)}</ul></div>}
    <div className="flex flex-wrap justify-end gap-2"><button className="btn-secondary" onClick={() => setPreview(v => !v)}><Eye size={14}/>{preview ? 'Скрыть конфигурацию' : 'Предпросмотр .rsc'}</button><button className="btn-primary" onClick={download} disabled={allErrors.length > 0}><Download size={14}/> Скачать .rsc</button></div>
    {preview && <div className={cardClass}><div className="flex items-center gap-2"><Server size={16}/><b className="text-sm">Предварительная конфигурация</b></div><pre className="text-[11px] leading-relaxed font-mono whitespace-pre-wrap break-all bg-mk-bg rounded p-3 max-h-[520px] overflow-auto">{config}</pre></div>}
    </fieldset>
    <div className="text-xs text-mk-mute">Важно: это первый этап конструктора. Генерация не является подтверждением готовности конфига к production. Перед применением необходимы полноценные проверки Bridge/VLAN filtering, DHCP network, L2TP/IPsec, OSPF adjacency, Firewall/NAT и откат.</div>
  </div>;
}
