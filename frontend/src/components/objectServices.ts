import {defaultDns} from './objectDns';
import {rosQuote,validIPv4} from './objectRouting';
export type WifiNet={enabled:boolean;ssid:string;vlan:string;auth:string;password:string;band24:boolean;band5:boolean;isolate:boolean};
export const defaultWifi=(guest=false):WifiNet=>({enabled:!guest,ssid:'',vlan:'',auth:'wpa2-wpa3-psk',password:'',band24:true,band5:true,isolate:guest});
export const defaultServices=()=>({...defaultDns(),wifiMode:'local',country:'',txPower:'',corpWifi:defaultWifi(),guestWifi:defaultWifi(true),radiusAddress:'',radiusSecret:'',capVlan:'',capAddress:'',radio24:'wifi2',radio5:'wifi1',ntpEnabled:false,ntpServers:'',timezone:'',snmpEnabled:false,snmpUser:'monitoring',snmpAddress:'',snmpAuthPassword:'',snmpEncryptionPassword:''});
export type Services=ReturnType<typeof defaultServices>;
const clean=(s:string)=> !/[\x00-\x1f\x7f]/.test(s);
const bytes=(s:string)=>new TextEncoder().encode(s).length;
const list=(s:string)=>s.split(',').map(x=>x.trim()).filter(Boolean);
const host=(s:string)=>validIPv4(s)||(!/^[\d.]+$/.test(s)&&s.length<=253&&s.includes('.')&&s.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(x)));
const cidr=(s:string)=>{const [ip,b,...r]=s.split('/');return !r.length&&validIPv4(ip)&&(b===undefined||/^(?:[1-9]|[12]\d|3[0-2])$/.test(b));};
export function buildServices(s:Services,p:{wifiEnabled:boolean;model:string;vlans:{id:string;tagged:string}[];ports:{name:string}[];guests:string;firewallProfile:string}){
 const errors:string[]=[],lines:string[]=[],inputRules:string[]=[];
 const ids=p.vlans.map(v=>String(Number(v.id))), guests=list(p.guests);
 if(s.timezone){if(!/^[A-Za-z0-9_+\-/]{1,80}$/.test(s.timezone))errors.push('Часовой пояс: некорректное имя.');else {try{new Intl.DateTimeFormat('en',{timeZone:s.timezone});lines.push(`/system clock set time-zone-autodetect=no time-zone-name=${rosQuote(s.timezone)}`);}catch{errors.push('Часовой пояс: укажите действующий IANA TZ.');}}}
 if(s.ntpEnabled){const servers=list(s.ntpServers);if(!servers.length||servers.some(x=>!host(x)))errors.push('NTP: укажите IPv4 или DNS-имена серверов.');else{lines.push('/system ntp client set enabled=yes');for(const a of new Set(servers))lines.push(`/system ntp client servers add address=${rosQuote(a)}`);}}
 if(s.snmpEnabled){if(p.firewallProfile==='custom')errors.push('SNMP: требуется Firewall-шаблон.');const a=list(s.snmpAddress);if(!a.length||a.some(x=>!cidr(x)))errors.push('SNMP: разрешённые IPv4/CIDR обязательны, /0 запрещён.');if(!/^[A-Za-z0-9_-]{1,32}$/.test(s.snmpUser)||s.snmpUser==='public'||[s.snmpAuthPassword,s.snmpEncryptionPassword].some(x=>bytes(x)<8||bytes(x)>64||!clean(x)))errors.push('SNMPv3: имя не public, два пароля 8–64 байта.');else if(a.length&&a.every(cidr)){lines.push('/snmp community remove [find where name="public"]',`/snmp community add name=${rosQuote(s.snmpUser)} addresses=${a.join(',')} security=private authentication-protocol=SHA1 authentication-password=${rosQuote(s.snmpAuthPassword)} encryption-protocol=AES encryption-password=${rosQuote(s.snmpEncryptionPassword)} read-access=yes write-access=no`,'/snmp set enabled=yes');for(const addr of new Set(a))for(const iface of ['LAN','VPN'])inputRules.push(`/ip firewall filter add chain=input action=accept in-interface-list=${iface} src-address=${addr} protocol=udp dst-port=161`);}}
 if(p.wifiEnabled){
 const cap=s.wifiMode==='capsman';if(!['local','capsman'].includes(s.wifiMode)||(!cap&&p.model!=='hAP ax²')||(cap&&!['hAP ax²','RB5009'].includes(p.model)))errors.push('Wi-Fi: локальный режим только hAP ax²; CAPsMAN только hAP ax² / RB5009.');
 if(!s.country.trim()||s.country.trim().toLowerCase()==='superchannel'||!clean(s.country)||bytes(s.country)>64)errors.push('Wi-Fi: укажите страну RouterOS.');
 if(s.txPower&&(!/^\d{1,2}$/.test(s.txPower)||Number(s.txPower)>30))errors.push('Wi-Fi: мощность 0–30 dBm или пусто.');
 const nets=[['corp',s.corpWifi],['guest',s.guestWifi]] as const;const active=nets.filter(([,n])=>n.enabled);
 if(!active.length)errors.push('Wi-Fi: включите хотя бы одну сеть.');
 if(active.length===2&&(s.corpWifi.ssid===s.guestWifi.ssid||s.corpWifi.vlan===s.guestWifi.vlan))errors.push('Wi-Fi: разные SSID и VLAN для корпоративной и гостевой сетей.');
 for(const [k,n] of active){if(!n.ssid.trim()||bytes(n.ssid)>32||!clean(n.ssid)||!ids.includes(n.vlan)||(!n.band24&&!n.band5))errors.push(`Wi-Fi ${k}: SSID 1–32 байта, существующий VLAN и диапазон обязательны.`);if((k==='guest')!==guests.includes(n.vlan)||p.firewallProfile==='custom')errors.push(`Wi-Fi ${k}: согласуйте гостевой VLAN с Firewall и выберите шаблон.`);if(!['wpa2-psk','wpa3-psk','wpa2-wpa3-psk','wpa2-eap','wpa3-eap'].includes(n.auth))errors.push('Wi-Fi: неизвестный тип авторизации.');if(n.auth.includes('psk')&&(!clean(n.password)||bytes(n.password)<8||bytes(n.password)>63))errors.push(`Wi-Fi ${k}: PSK 8–63 байта.`);}
 if(active.some(([,n])=>n.auth.includes('eap'))){if(!validIPv4(s.radiusAddress)||!s.radiusSecret||!clean(s.radiusSecret))errors.push('RADIUS: IPv4 и shared secret обязательны.');else lines.push(`/radius add service=wireless address=${s.radiusAddress} secret=${rosQuote(s.radiusSecret)}`);}
 if(cap){if(!ids.includes(s.capVlan)||guests.includes(s.capVlan)||!validIPv4(s.capAddress)||p.firewallProfile==='custom')errors.push('CAPsMAN: доверенный VLAN и IPv4 CAP обязательны.');else inputRules.push(`/ip firewall filter add chain=input action=accept in-interface=vlan${s.capVlan} src-address=${s.capAddress} protocol=udp dst-port=5246,5247`);}
 else if(!/^wifi[1-9]\d*$/.test(s.radio24)||!/^wifi[1-9]\d*$/.test(s.radio5)||s.radio24===s.radio5||p.ports.some(x=>[s.radio24,s.radio5,'rz-guest24','rz-guest5'].includes(x.name)))errors.push('Wi-Fi: проверьте имена радиоинтерфейсов; не включайте их в физические порты.');
 if(!errors.length){
 lines.push('# --- Wi-Fi (RouterOS 7.13+, wifi-qcom AX only) ---');
 const extra=new Map<string,string[]>();
 for(const band of ['24','5'] as const){const selected=active.filter(([,n])=>band==='24'?n.band24:n.band5);if(!selected.length)continue;const radio=band==='24'?s.radio24:s.radio5;
 for(const [i,[k,n]] of selected.entries()){
 const cfg=`rz-${k}-${band}`,auth=n.auth==='wpa2-wpa3-psk'?'wpa2-psk,wpa3-psk':n.auth;
 lines.push(`/interface wifi configuration add name=${cfg} mode=ap ssid=${rosQuote(n.ssid)} country=${rosQuote(s.country)} channel.band=${band==='24'?'2ghz-ax':'5ghz-ax'} security.authentication-types=${auth}${n.auth.includes('psk')?' security.passphrase='+rosQuote(n.password):''} datapath.client-isolation=${n.isolate?'yes':'no'}${' datapath.vlan-id='+n.vlan+(cap?'':' datapath.bridge=bridge-lan')}${s.txPower?' tx-power='+Number(s.txPower):''}`);
 if(!cap){const iface=i===0?radio:`rz-guest${band}`;if(i===0)lines.push(`/interface wifi set [find where name=${rosQuote(radio)}] configuration=${cfg} disabled=yes`);else lines.push(`/interface wifi add name=${iface} master-interface=${radio} configuration=${cfg} disabled=yes`);extra.set(n.vlan,[...(extra.get(n.vlan)||[]),iface]);}
 }
 if(cap)lines.push(`/interface wifi provisioning add action=create-dynamic-enabled supported-bands=${band==='24'?'2ghz-ax':'5ghz-ax'} master-configuration=rz-${selected[0][0]}-${band}${selected.length>1?' slave-configurations=rz-'+selected[1][0]+'-'+band:''}`);
 }
 if(cap)lines.push(`/interface wifi capsman set enabled=yes interfaces=vlan${s.capVlan}`,'# Configure remote AX CAP local bridge and tagged uplink separately.');
 else {for(const band of ['24','5'] as const){if(!active.some(([,n])=>band==='24'?n.band24:n.band5))lines.push(`/interface wifi set [find where name=${rosQuote(band==='24'?s.radio24:s.radio5)}] disabled=yes`);}for(const [id,ifaces] of extra){const v=p.vlans.find(x=>String(Number(x.id))===id)!;lines.push(`/interface bridge vlan set [find where bridge=bridge-lan and vlan-ids=${id}] tagged=${[...new Set(['bridge-lan',...list(v.tagged),...ifaces])].join(',')}`);}for(const band of ['24','5'] as const){const selected=active.filter(([,n])=>band==='24'?n.band24:n.band5);if(selected.length)lines.push(`/interface wifi set [find where name=${rosQuote(band==='24'?s.radio24:s.radio5)}] disabled=no`);if(selected.length>1)lines.push(`/interface wifi set [find where name=rz-guest${band}] disabled=no`);}}
 }
 }
 return {errors,config:errors.length?'':lines.join('\n'),inputRules:errors.length?[]:inputRules};
}
