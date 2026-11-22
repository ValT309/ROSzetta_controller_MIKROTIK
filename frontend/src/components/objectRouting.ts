// Offline RouterOS 7 draft generation. Secrets never sent to the API.
export type Tunnel = {enabled?:boolean;name:string; server:string; user:string; password:string; ipsecSecret:string; ospfKey:string; cost:string};
type Params = {bridge?:{subnet:string;gateway:string;ospf:boolean};loopbackAddress?:string;wanAddress?:string;wanMode:string; wanPort:string; vlans:{id:string;subnet:string}[]; ports:{name:string}[]; tunnels:Tunnel[]; routerId:string; area:string; profile:string; management:string; guests:string; corporate:string};
export const validIPv4 = (s:string) => /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(s) && s.split('.').every(x=>Number(x)<=255);
const list = (s:string) => s.split(',').map(x=>x.trim()).filter(Boolean);
const prefix = (s:string) => {const p=s.split('/');return p.length<=2 && validIPv4(p[0]) && (p.length===1 || /^(0|[1-9]|[12]\d|3[0-2])$/.test(p[1]));};
const identifier = (s:string) => /^[A-Za-z0-9_-]{1,32}$/.test(s);
const hostname = (s:string) => validIPv4(s) || (s.length<=253 && s.includes('.') && !/^[\d.]+$/.test(s) && s.split('.').every(x=>/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(x)));
export const rosQuote = (s:string) => '"'+s.replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\$/g,'\\$').replace(/\r/g,'\\r').replace(/\n/g,'\\n').replace(/\t/g,'\\t')+'"';
const clean = (s:string) => !/[\x00-\x1f\x7f]/.test(s);
export const loopbackIP = (value:string) => {
  const ip=value.trim().replace(/\/32$/, '');
  return validIPv4(ip)&&ip.startsWith('10.') ? ip : '';
};
const inSubnet=(ip:string,cidr:string)=>{
  const [address,bits]=cidr.split('/');
  if(!validIPv4(address)||! /^(0|[1-9]|[12]\d|3[0-2])$/.test(bits||''))return false;
  const n=(s:string)=>s.split('.').reduce((v,x)=>v*256+Number(x),0);
  const size=2**(32-Number(bits));return Math.floor(n(ip)/size)===Math.floor(n(address)/size);
};
// Remove contained networks only within one address list; normalize host bits.
export function compactNetworks(values:string[]):string[] {
 const num=(x:string)=>x.split('.').reduce((n,o)=>n*256+Number(o),0);
 const fmt=(n:number)=>[24,16,8,0].map(b=>(n>>>b)&255).join('.');
 const items=values.filter(prefix).map(v=>{const [a,b='32']=v.split('/');const bits=Number(b),size=2**(32-bits);return {bits,start:Math.floor(num(a)/size)*size,size};}).sort((a,b)=>a.bits-b.bits||a.start-b.start);
 const out:typeof items=[];
 for(const x of items)if(!out.some(y=>x.start>=y.start&&x.start+x.size<=y.start+y.size))out.push(x);
 return out.map(x=>fmt(x.start)+(x.bits===32?'/32':'/'+x.bits));
}
export function buildRouting(p:Params) {
  const lo=loopbackIP(p.loopbackAddress||'');
  const errors:string[]=[];const lines:string[]=[];
  const enabled=p.tunnels.filter(t=>t.enabled ?? [t.server,t.user,t.password,t.ipsecSecret,t.ospfKey].some(Boolean));
  const routerId=p.routerId || (enabled.length ? lo : '');
  if(p.loopbackAddress?.trim()&&!lo) errors.push('Loopback: укажите IPv4 из 10.0.0.0/8 с маской /32 или без маски.');
  if(lo&&((p.vlans.some(v=>inSubnet(lo,v.subnet))||(p.bridge&&inSubnet(lo,p.bridge.subnet)))||(p.wanMode==='static'&&inSubnet(lo,p.wanAddress||'')))) errors.push('Loopback: адрес пересекается с локальной VLAN или статической WAN-сетью.');
  if(p.ports.some(x=>x.name==='lo')) errors.push('Интерфейс lo зарезервирован для Loopback.');
  const names=new Set(['lo','bridge-lan','pppoe-out1',...p.ports.map(x=>x.name),...p.vlans.map(v=>`vlan${Number(v.id)}`)]);
  const vlanIds=p.vlans.map(v=>String(Number(v.id)));
  const guests=list(p.guests); const management=list(p.management);const corp=list(p.corporate);
  if(guests.some(x=>!vlanIds.includes(x)) || new Set(guests).size!==guests.length) errors.push('Гостевые VLAN: укажите существующие уникальные ID.');
  if([...management,...corp].some(x=>!prefix(x))) errors.push('Firewall: адреса должны быть IPv4 или IPv4/CIDR.');
  if(management.some(x=>x.endsWith('/0'))) errors.push('Firewall: управление из всей сети IPv4 запрещено.');
  if(p.profile!=='custom'&&!management.length) errors.push('Firewall: укажите разрешённые IP/CIDR управления (LAN или VPN).');
  if(!['standard','strict','custom'].includes(p.profile)) errors.push('Неизвестный Firewall-профиль.');
  for(const t of enabled){
    if(!identifier(t.name)||names.has(t.name)) errors.push('L2TP: некорректное или повторное имя интерфейса.');
    names.add(t.name);
    if(!hostname(t.server)||!t.user.trim()||!t.password||![t.user,t.password,t.ipsecSecret,t.ospfKey].every(clean)) errors.push(`L2TP ${t.name}: заполните сервер, логин и пароль; ключи необязательны. Управляющие символы запрещены.`);
    if(!/^\d{1,5}$/.test(t.cost)||Number(t.cost)<1||Number(t.cost)>65535) errors.push(`L2TP ${t.name}: стоимость OSPF 1–65535.`);
    if(routerId&&t.ospfKey&&new TextEncoder().encode(t.ospfKey).length>16) errors.push(`L2TP ${t.name}: OSPF MD5 ключ должен содержать 1–16 байт.`);
    if(!routerId&&t.ospfKey) errors.push('OSPF: укажите Router ID.');
  }
  if(routerId&&(!validIPv4(routerId)||routerId==='0.0.0.0'||!identifier(p.area)||!enabled.length)) errors.push('OSPF: укажите уникальный IPv4 Router ID, имя area и хотя бы один туннель.');
  if(enabled.length===2&&routerId&&Number(enabled[0].cost)>=Number(enabled[1].cost)) errors.push('OSPF: стоимость резервного туннеля должна быть больше основной.');
  if(errors.length) return {errors,config:''};
  if(lo) lines.push('# --- Loopback ---', ':if ([:len [/interface find where name="lo"]] = 0) do={ /interface bridge add name=lo protocol-mode=none }', `/ip address add address=${lo}/32 interface=lo comment="ROSzetta loopback"`);
  lines.push('# --- L2TP / IPsec ---');
  for(const t of enabled) lines.push(`/interface l2tp-client add name=${t.name} connect-to=${rosQuote(t.server)} user=${rosQuote(t.user)} password=${rosQuote(t.password)} ${t.ipsecSecret?`use-ipsec=yes ipsec-secret=${rosQuote(t.ipsecSecret)}`:"use-ipsec=no"} max-mtu=1400 max-mru=1400 add-default-route=no disabled=no`);
  lines.push('# --- OSPF ---');
  if(routerId){
    lines.push(`/routing ospf instance add name=ospf-v2 version=2 router-id=${routerId}`,`/routing ospf area add name=${p.area} instance=ospf-v2 area-id=0.0.0.0`);
    for(const t of enabled)lines.push(`/routing ospf interface-template add area=${p.area} interfaces=${t.name} type=ptp${t.ospfKey?` auth=md5 auth-id=1 auth-key=${rosQuote(t.ospfKey)}`:""} cost=${Number(t.cost)}`);
    if(lo)lines.push(`/routing ospf interface-template add area=${p.area} interfaces=lo passive`);
    if(p.bridge?.ospf)lines.push(`/routing ospf interface-template add area=${p.area} interfaces=bridge-lan passive`);
    for(const id of vlanIds.filter(x=>!guests.includes(x)))lines.push(`/routing ospf interface-template add area=${p.area} interfaces=vlan${id} passive`);
  }
  lines.push('# --- IPv4 Firewall / NAT ---');
  if(p.profile==='custom'){lines.push('# Firewall intentionally omitted; laboratory only.');return {errors,config:lines.join('\n')};}
  for(const n of ['WAN','LAN','VPN','GUEST'])lines.push(`/interface list add name=${n}`);
  const wan=p.wanMode==='pppoe'?'pppoe-out1':p.wanPort;
  lines.push(`/interface list member add list=WAN interface=${wan}`);
  if(wan!==p.wanPort) lines.push(`/interface list member add list=WAN interface=${p.wanPort}`);
  if(p.bridge)lines.push(`/interface list member add list=LAN interface=bridge-lan`);
  for(const id of vlanIds) {lines.push(`/interface list member add list=LAN interface=vlan${id}`);if(guests.includes(id))lines.push(`/interface list member add list=GUEST interface=vlan${id}`);}
  for(const t of enabled) lines.push(`/interface list member add list=VPN interface=${t.name}`);
  for(const server of new Set(enabled.filter(t=>t.ipsecSecret).map(t=>t.server.toLowerCase()))) lines.push(`/ip firewall address-list add list=ROSZETTA_VPN_PEERS address=${rosQuote(server)}`);
  for(const a of compactNetworks(['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16',...p.vlans.map(v=>v.subnet),...(p.bridge?[p.bridge.subnet]:[]),...corp]))lines.push(`/ip firewall address-list add list=CORP_LAN address=${a}`);
  for(const a of compactNetworks(management))lines.push(`/ip firewall address-list add list=ROSZETTA_MGMT address=${a}`);
  const rule=(chain:string,body:string)=>lines.push(`/ip firewall filter add chain=${chain} ${body}`);
  rule('input','action=accept connection-state=established,related');
  rule('input','action=drop connection-state=invalid');
  rule('input','action=accept protocol=icmp');
  if(p.wanMode==='dhcp')rule('input','action=accept in-interface-list=WAN protocol=udp src-port=67 dst-port=68');
  rule('input','action=accept in-interface-list=LAN protocol=udp src-port=68 dst-port=67');
  if(enabled.some(t=>t.ipsecSecret)){rule('input','action=accept in-interface-list=WAN src-address-list=ROSZETTA_VPN_PEERS protocol=udp dst-port=500,4500');rule('input','action=accept in-interface-list=WAN src-address-list=ROSZETTA_VPN_PEERS protocol=ipsec-esp');rule('input','action=accept in-interface-list=WAN protocol=udp dst-port=1701 ipsec-policy=in,ipsec');}
  if(routerId)rule('input','action=accept in-interface-list=VPN protocol=ospf');
  rule('input','action=drop in-interface-list=GUEST');
  for(const intf of ['LAN','VPN'])rule('input',`action=accept in-interface-list=${intf} src-address-list=ROSZETTA_MGMT protocol=tcp dst-port=22,8291,8728,8729`);
  rule('input','action=drop');
  rule('forward','action=accept connection-state=established,related');
  rule('forward','action=drop connection-state=invalid');
  rule('forward','action=drop in-interface-list=GUEST dst-address-list=CORP_LAN');
  rule('forward','action=accept in-interface-list=GUEST out-interface-list=WAN');
  rule('forward','action=drop in-interface-list=GUEST');
  rule('forward','action=drop out-interface-list=GUEST');
  rule('forward','action=accept in-interface-list=LAN out-interface-list=WAN');
  rule('forward','action=accept in-interface-list=LAN out-interface-list=VPN');
  if(p.profile==='standard'){rule('forward','action=accept in-interface-list=VPN out-interface-list=LAN');rule('forward','action=accept in-interface-list=LAN out-interface-list=LAN');}
  rule('forward','action=drop');
  lines.push('/ip firewall nat add chain=srcnat action=masquerade out-interface-list=WAN ipsec-policy=out,none');
  return {errors,config:lines.join('\n')};
}

// Largest contiguous usable DHCP range excluding router IP; manual override in UI.
export function suggestPool(cidr:string,gateway:string):{poolStart:string;poolEnd:string}|null {
 const [ip,bits,...rest]=cidr.trim().split('/');
 if(rest.length||!validIPv4(ip)||!validIPv4(gateway)||! /^(?:[0-9]|[12][0-9]|30)$/.test(bits||''))return null;
 const num=(x:string)=>x.split('.').reduce((n,o)=>n*256+Number(o),0);
 const fmt=(n:number)=>[24,16,8,0].map(b=>(n>>>b)&255).join('.');
 const size=2**(32-Number(bits)),lo=Math.floor(num(ip)/size)*size,hi=lo+size-1,g=num(gateway);
 if(num(ip)!==lo||g<=lo||g>=hi)return null;
 const left=g-lo-1,right=hi-g-1;
 if(!left&&!right)return null;
 return left>right?{poolStart:fmt(lo+1),poolEnd:fmt(g-1)}:{poolStart:fmt(g+1),poolEnd:fmt(hi-1)};
}
