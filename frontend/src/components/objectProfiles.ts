// Stable IDs preserve existing saved objects and history.
export const profiles = [
 {id:'office',label:'Офис',guest:true,access:true},
 {id:'warehouse',label:'Склад',guest:false,access:true},
 {id:'production',label:'Стройка',guest:false,access:true},
 {id:'retail',label:'Отдел продаж',guest:true,access:false},
] as const;
export const profileLabel=(id:string)=>profiles.find(p=>p.id===id)?.label||id;
export const vpnServers=['vpngate1.gk-nvm.ru','vpngate2.gk-nvm.ru'] as const;
export const commonDefaults={ntpServers:'10.110.0.15,10.110.0.16',timezone:'Europe/Moscow'};
export const networkRoles=[{name:'video',label:'Видеонаблюдение'}, {name:'users',label:'Пользователи'}, {name:'voip',label:'Телефония'}, {name:'corp-wifi',label:'Корпоративный Wi-Fi'}, {name:'guest',label:'Гостевой Wi-Fi'}, {name:'access-control',label:'СКУД'}] as const;
export function recommendedRoles(id:string){const p=profiles.find(p=>p.id===id);return p?networkRoles.filter(r=>(r.name!=='guest'||p.guest)&&(r.name!=='access-control'||p.access)):[];}
export function planProfile(id:string,existing:{id:string;name:string}[],chosen:Record<string,string>){
 const additions:{id:string;name:string}[]=[]; const used=new Set(existing.map(v=>Number(v.id)));
 const roles=recommendedRoles(id);if(!roles.length)throw new Error('Неизвестный профиль');
 for(const r of roles){if(existing.some(v=>v.name.toLowerCase()===r.name))continue;
 const value=(chosen[r.name]||'').trim();if(!value)continue;
 const n=Number(value);if(!/^\d{1,4}$/.test(value)||n<1||n>4094||used.has(n))throw new Error('Некорректный или повторный VLAN ID: '+r.label);
 used.add(n);additions.push({id:String(n),name:r.name});}
 return additions;
}
