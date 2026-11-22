export type AutomationDevice = {id:number;name:string;identity?:string|null;host:string;kind?:string;group_name?:string|null;model?:string|null;status?:string;username?:string;port?:number;use_tls?:boolean;location?:string|null;purpose?:string|null;inventory_number?:string|null;comment?:string|null};
export type DeviceFilters = {search:string;kind:string;site:string;status:string;onlySelected:boolean;sort:string};
export const initialDeviceFilters:DeviceFilters={search:'',kind:'all',site:'all',status:'all',onlySelected:false,sort:'name'};
const norm=(s:unknown)=>String(s??'').trim().toLocaleLowerCase('ru');
export function filterAutomationDevices<T extends AutomationDevice>(devices:T[],selected:number[],f:DeviceFilters):T[]{
 const ids=new Set(selected), q=norm(f.search);
 return devices.filter(d=>(!q||[d.name,d.identity,d.host,d.model,d.group_name,d.location,d.purpose,d.inventory_number,d.comment].some(v=>norm(v).includes(q)))&&(f.kind==='all'||d.kind===f.kind)&&(f.site==='all'||(f.site==='none'?!d.group_name?.trim():`site:${d.group_name?.trim()}`===f.site))&&(f.status==='all'||(f.status==='unknown'?!['up','down'].includes(d.status||''):d.status===f.status))&&(!f.onlySelected||ids.has(d.id))).sort((a,b)=>{const key=(d:T)=>f.sort==='host'?d.host:f.sort==='model'?d.model||'':d.identity||d.name;return key(a).localeCompare(key(b),'ru',{numeric:true,sensitivity:'base'})||a.id-b.id});
}
export function selectVisible(selected:number[],visible:AutomationDevice[]):number[]{return [...new Set([...selected,...visible.map(d=>d.id)])]}
