import {compactNetworks} from './objectRouting';
// Clean configuration only: never use these commands to patch a live device blindly.
export function buildHardening(profile:string,management:string){
 if(profile==='custom')return '';
 const addresses=compactNetworks(management.split(',').map(x=>x.trim()).filter(Boolean));
 if(!addresses.length||addresses.includes('0.0.0.0/0'))return '';
 const lines=['# --- Management / IPv6 (IPv4-only site policy) ---'];
 for(const service of ['telnet','ftp','www','www-ssl'])lines.push(`/ip service set [find where name=${service}] disabled=yes`);
 for(const service of ['ssh','winbox','api','api-ssl'])lines.push(`/ip service set [find where name=${service}] address=${addresses.join(',')}`);
 lines.push('/tool mac-server set allowed-interface-list=none','/tool mac-server mac-winbox set allowed-interface-list=none','/tool mac-server ping set enabled=no','/ip neighbor discovery-settings set discover-interface-list=none');
 lines.push('/ipv6 firewall filter add chain=input action=accept connection-state=established,related','/ipv6 firewall filter add chain=input action=drop connection-state=invalid','/ipv6 firewall filter add chain=input action=accept protocol=icmpv6','/ipv6 firewall filter add chain=input action=drop','/ipv6 firewall filter add chain=forward action=drop');
 return lines.join('\n');
}
