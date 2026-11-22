// Return section counts only; never expose command arguments or secrets.
export function summarizeSections(text:string):Record<string,number>{
 const counts:Record<string,number>=Object.create(null);let section='';
 for(const line of text.split(/\r?\n/)){
  const s=line.trim();if(!s||s.startsWith('#'))continue;
  const absolute=s.match(/^\/([a-z0-9/-]+(?: [a-z0-9/-]+)*?)(?:\s+(?:add|set|remove|enable|disable|move|reset)(?:\s|$)|$)/i);
  if(absolute){section='/'+absolute[1];if(/^\/[^=]+?\s+(?:add|set|remove|enable|disable|move|reset)(?:\s|$)/i.test(s))counts[section]=(counts[section]||0)+1;}
  else if(s.startsWith('/'))section='';
  else if(section&&/^(?:add|set|remove|enable|disable|move|reset)(?:\s|$)/i.test(s))counts[section]=(counts[section]||0)+1;
 }return counts;
}

export type DiffRow={kind:'added'|'removed';line:number;text:string};
const action='add|set|remove|enable|disable|move|reset';
const absolute=new RegExp(`^(/[-\\w/]+(?:\\s+[-\\w/]+)*?)\\s+(${action})(?:\\s+(.*))?$`,'i');
const relative=new RegExp(`^(${action})(?:\\s+(.*))?$`,'i');
const allowedPaths=/^\/(?:interface|ip|ipv6|routing|system|snmp|radius|tool|ppp|queue)(?: [\w-]+)*$/;
function normalizedLines(source:string):string[]{
 if(source.length>300000)throw new Error('too-large');
 const lines:string[]=[];let section='',pending='',header='';
 for(const raw of source.split(/\r?\n/)){
  const line=raw.trim(); if(!pending&&(!line||line.startsWith('#')))continue;
  if(/(?:^|[^\\])(?:\\\\)*\\$/.test(line)){pending+=line.slice(0,-1)+' ';continue;}
  const full=pending+line;pending='';
  const m=full.match(absolute);
  if(header&&!full.match(relative)){lines.push(header);header='';}
  if(m){section=m[1].replace(/\//g,' ').trim();section='/'+section.replace(/\s+/g,' ');lines.push(`${section} ${m[2]}${m[3]?' '+m[3]:''}`);continue;}
  if(/^\/[\w /-]+$/.test(full)){section='/'+full.replace(/\//g,' ').trim().replace(/\s+/g,' ');header=full;continue;}
  const r=full.match(relative);if(r&&section){header='';lines.push(`${section} ${full}`);continue;}
  lines.push(full);if(full.startsWith('/'))section='';
 }
 if(header)lines.push(header);
 if(pending)lines.push(pending);
 if(lines.length>1500)throw new Error('too-large');return lines;
}
// Display only allowlisted structured fields. Unknown fields, comments, quoted
// script bodies, selectors, and unparsed lines are hidden in the textual diff.
const numericFields=new Set(['address','src-address','dst-address','gateway','ranges','dns-server','dns-servers','servers','vlan-id','vlan-ids','pvid','cost','distance','mtu','max-mtu','max-mru','mru','dst-port','src-port','router-id','area-id','network','networks','forward-to','connect-to','port']);
const nameFields=new Set(['name','interface','interfaces','bridge','tagged','untagged','in-interface','out-interface','in-interface-list','out-interface-list','list','src-address-list','dst-address-list','address-pool','area','instance','chain','action','protocol','connection-state','frame-types','disabled','ingress-filtering','vlan-filtering','add-default-route','use-peer-dns','allow-remote-requests','use-ipsec','auth','type','match-subdomain','protocol-mode','passive']);
// Only fixed command syntax is shown for a line that is not safely tokenized.
function safeLine(line:string):string{
 const m=line.match(absolute);if(!m)return '[Не разобранная строка / скрипт скрыты]';
 const path=m[1];if(!allowedPaths.test(path))return '[Неизвестный раздел скрыт]';
 if(/\/system (?:script|scheduler)|\/tool netwatch|\/ip hotspot user|\/ppp secret/.test(path))return `${path} ${m[2]} [параметры скрыты]`;
 let rest=m[3]||'';const out:string[]=[];
 while(rest){
  const t=rest.match(/^([a-z][a-z0-9-]*)=("(?:[^"\\]|\\.)*"|[^\s"'`;{}\[\]$\\]+)(?:\s+|$)/i);
  if(!t){out.push('[остальные параметры скрыты]');break;}
  const key=t[1];const v=t[2];const unquoted=v.startsWith('"')?v.slice(1,-1):v;
  const safe=(numericFields.has(key)&&/^[0-9.,:/-]+$/.test(unquoted))||(nameFields.has(key)&&/^[a-zA-Z0-9_.!,:/-]{1,128}$/.test(unquoted));
  // Never show unknown keys, e.g. custom credentials, or their values.
  out.push(safe?`${key}=${unquoted}`:'[параметр скрыт]');rest=rest.slice(t[0].length);
 }
 return `${path} ${m[2]}${out.length?' '+out.join(' '):''}`;
}
// Ordered textual LCS. No command execution, no semantic reconciliation.
export function lineDiff(before:string,after:string):DiffRow[]{
 const a=normalizedLines(before),b=normalizedLines(after),w=b.length+1;
 const dp=new Uint16Array((a.length+1)*w);
 for(let i=a.length-1;i>=0;i--)for(let j=b.length-1;j>=0;j--)dp[i*w+j]=a[i]===b[j]?dp[(i+1)*w+j+1]+1:Math.max(dp[(i+1)*w+j],dp[i*w+j+1]);
 const out:DiffRow[]=[];let i=0,j=0;
 while(i<a.length||j<b.length){if(i<a.length&&j<b.length&&a[i]===b[j]){i++;j++;continue;}
  if(i<a.length&&(j===b.length||dp[(i+1)*w+j]>=dp[i*w+j+1])){out.push({kind:'removed',line:i+1,text:safeLine(a[i])});i++;}
  else{out.push({kind:'added',line:j+1,text:safeLine(b[j])});j++;}
 }return out;
}
