export function formatDuration(seconds:number):string {
 if(!Number.isSafeInteger(seconds)||seconds<0)return '—';
 const parts:string[]=[];
 for(const [size,unit] of [[86400,'д'],[3600,'ч'],[60,'мин'],[1,'с']] as const){const n=Math.floor(seconds/size);seconds%=size;if(n)parts.push(`${n} ${unit}`)}
 return parts.join(' ')||'0 с';
}
export function displayAlertMessage(message:string):string {
 const match=/^uptime (\d+)s\s*(?:→|->)\s*(\d+)s$/.exec(message.trim());
 const manual=/^Uptime упал с (\d+)s до (\d+)s без штатной команды reboot\.$/.exec(message.trim());
 if(manual)return `Время работы сократилось с ${formatDuration(Number(manual[1]))} до ${formatDuration(Number(manual[2]))} без штатной команды reboot.`;
 return match?`Время работы: ${formatDuration(Number(match[1]))} → ${formatDuration(Number(match[2]))}`:message;
}
