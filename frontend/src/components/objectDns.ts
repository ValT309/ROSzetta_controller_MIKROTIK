import {validIPv4} from './objectRouting';
export const defaultDns=()=>({splitDns:true,dnsDomain:'gk-nvm.ru',dnsCorporate:'10.110.0.15,10.110.0.16',dnsSubdomains:true,dnsExceptions:[{domain:'vpngate1.gk-nvm.ru',servers:'77.88.8.8,77.88.8.88,195.208.4.1'},{domain:'vpngate2.gk-nvm.ru',servers:'77.88.8.8,77.88.8.88,195.208.4.1'},{domain:'bitrix.gk-nvm.ru',servers:'77.88.8.8,77.88.8.1'}]});
const list=(s:string)=>s.split(',').map(x=>x.trim()).filter(Boolean);
const servers=(s:string)=>{const a=list(s);return a.length&&a.every(validIPv4)?[...new Set(a)].join(','):'';};
const domain=(s:string)=>{const d=s.trim().toLowerCase();return d.length<=253&&d.includes('.')&&!/^[0-9.]+$/.test(d)&&d.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))?d:'';};
export function buildDns(s:ReturnType<typeof defaultDns>,publicDns:string,vlans:{id:string;subnet:string;gateway:string;dhcp:boolean}[],guests:string,profile:string,tunnels:{enabled:boolean;server:string}[]=[],bridge?:{subnet:string;gateway:string}){
 const errors:string[]=[],inputRules:string[]=[],lines:string[]=[],enable:string[]=[];
 const pub=servers(publicDns);if(!pub)errors.push('DNS: укажите публичные IPv4-серверы.');
 if(pub)lines.push('# --- DNS ---',`/ip dns set servers=${pub} allow-remote-requests=no`);
 if(s.splitDns){
  if(profile==='custom')errors.push('Split DNS: требуется Firewall-шаблон.');
  const corp=domain(s.dnsDomain),up=servers(s.dnsCorporate);if(!corp||!up)errors.push('Split DNS: корпоративный домен и IPv4-серверы обязательны.');
  const seen=new Set<string>();const exceptions=s.dnsExceptions.map(r=>({domain:domain(r.domain),servers:servers(r.servers)}));
  for(const r of exceptions){if(!r.domain||!r.servers||r.domain===corp||seen.has(r.domain))errors.push('Split DNS: проверьте уникальность доменов и IPv4 исключений.');seen.add(r.domain);}
  for(const t of tunnels.filter(t=>t.enabled)){const h=domain(t.server);if(h&&corp&&(h===corp||(s.dnsSubdomains&&h.endsWith('.'+corp)))&&!seen.has(h))errors.push('Split DNS: VPN-шлюз '+h+' должен иметь публичное исключение.');}
  if(!errors.length){
   lines.push('# Requires RouterOS DNS Forwarders support; exact exceptions first.');
   const groups=new Map<string,string>();
   for(const r of exceptions){const key=r.servers.split(',').sort().join(',');let group=groups.get(key);if(!group){group=`rz-dns-ex-${groups.size+1}`;groups.set(key,group);lines.push(`/ip dns forwarders add name=${group} dns-servers=${r.servers}`);}lines.push(`/ip dns static add name=${r.domain} type=FWD forward-to=${group} match-subdomain=no disabled=no`);}
   lines.push(`/ip dns forwarders add name=rz-dns-corp dns-servers=${up}`,`/ip dns static add name=${corp} type=FWD forward-to=rz-dns-corp match-subdomain=${s.dnsSubdomains?'yes':'no'} disabled=no`);
   const guestIds=list(guests).map(Number);
   for(const v of vlans){if(guestIds.includes(Number(v.id)))continue;const id=Number(v.id);const [ip,bits,...rest]=v.subnet.split('/');if(!/^\d+$/.test(v.id)||id<1||id>4094||!validIPv4(ip)||!/^([0-9]|[12]\d|3[0-2])$/.test(bits||'')||rest.length||!validIPv4(v.gateway)){errors.push('Split DNS: проверьте VLAN и адреса.');continue;}
    for(const proto of ['udp','tcp'])inputRules.push(`/ip firewall filter add chain=input action=accept in-interface=vlan${id} src-address=${v.subnet} protocol=${proto} dst-port=53`);
    // DHCP DNS is emitted once by the network generator.
   }
   if(bridge)for(const proto of ['udp','tcp'])inputRules.push(`/ip firewall filter add chain=input action=accept in-interface=bridge-lan src-address=${bridge.subnet} protocol=${proto} dst-port=53`);
   // IPv6 DNS access is not supported; block it explicitly before enabling the resolver.
   enable.unshift('/ipv6 firewall filter add chain=input action=drop protocol=udp dst-port=53','/ipv6 firewall filter add chain=input action=drop protocol=tcp dst-port=53');
   enable.push('/ip dns set allow-remote-requests=yes');
  }
 }
 return {errors,config:errors.length?'':lines.join('\n'),inputRules:errors.length?[]:inputRules,enableConfig:errors.length?'':enable.join('\n')};
}
