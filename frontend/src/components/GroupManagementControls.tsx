import {useEffect,useState} from 'react';
import {api} from '@/api/client';

const policies=['local','telnet','ssh','ftp','reboot','read','write','policy','test','winbox','password','web','sniff','sensitive','api','romon','rest-api'];
const modes={create:'Создать',upsert:'Создать или дополнить права',add:'Добавить права',remove:'Убрать права',replace:'Заменить права',delete:'Удалить пустую группу',move:'Перенести пользователя'} as const;
const presets=[
 {name:'ROSzetta',group_name:'roszetta',policies:['ssh','ftp','reboot','read','write','policy','test','sensitive','api']},
 {name:'Мониторинг',group_name:'nvm_monitoring',policies:['read','api']},
 {name:'Инженер',group_name:'nvm_engineer',policies:['read','write','ssh','winbox','test','api']},
 {name:'Full',group_name:'nvm_admin',policies:[...policies]},
];
type Mode=keyof typeof modes;
type Template={id:number;name:string;group_name:string;policies:string[]};
export type GroupInput={group_name:string;group_mode:Mode;group_user:string;group_policies:string[]};
const endpoint='/devices/stage2/group-templates';
function message(error:unknown){const e=error as {response?:{data?:{detail?:unknown}}};return typeof e.response?.data?.detail==='string'?e.response.data.detail:'Не удалось выполнить операцию с шаблоном';}
const validName=(value:string)=>/^[A-Za-z0-9_.-]{1,32}$/.test(value.trim());

export default function GroupManagementControls({count,busy,onInventory,onPreview,templatesOnly=false}:{count:number;busy:boolean;templatesOnly?:boolean;onInventory:()=>void;onPreview:(spec:GroupInput)=>void}){
 const [name,setName]=useState('roszetta'),[mode,setMode]=useState<Mode>('upsert'),[username,setUsername]=useState(''),[rights,setRights]=useState<string[]>([...presets[0].policies]);
 const [templates,setTemplates]=useState<Template[]>([]),[templateName,setTemplateName]=useState(''),[selectedTemplate,setSelectedTemplate]=useState<number|null>(null),[templateBusy,setTemplateBusy]=useState(false),[error,setError]=useState(''),[notice,setNotice]=useState('');
 useEffect(()=>{if(templatesOnly)setMode('upsert')},[templatesOnly]);
 const needsRights=['create','upsert','add','remove','replace'].includes(mode);
 const validGroup=validName(name)&&!['full','read','write'].includes(name.trim().toLowerCase());
 const valid=validGroup&&(!needsRights||rights.length>0)&&(mode!=='move'||validName(username));
 const load=async()=>setTemplates((await api.get<Template[]>(endpoint)).data);
 useEffect(()=>{let active=true;api.get<Template[]>(endpoint).then(r=>{if(active)setTemplates(r.data)}).catch(e=>{if(active)setError(message(e))});return()=>{active=false}},[]);
 function useTemplate(t:{name:string;group_name:string;policies:string[]}){setName(t.group_name);setRights([...t.policies]);setMode('upsert');setTemplateName(t.name);setError('');setNotice('');}
 async function saveTemplate(){
  if(!validGroup||!rights.length||!templateName.trim()||templateBusy)return;
  const existing=templates.find(t=>t.name===templateName.trim());
  if(existing&&!window.confirm(`Заменить шаблон «${existing.name}»? Группы на MikroTik не меняются.`))return;
  setTemplateBusy(true);setNotice('');setError('');
  try {const r=await api.post<Template>(endpoint,{name:templateName.trim(),group_name:name.trim(),policies:rights,replace:Boolean(existing)});await load();setSelectedTemplate(r.data.id);setNotice('Шаблон сохранён в контроллере');}
  catch(e){setError(message(e))}finally{setTemplateBusy(false)}
 }
 async function removeTemplate(){
  if(!selectedTemplate||templateBusy||!window.confirm('Удалить шаблон из ROSzetta? Это не удаляет группы на устройствах.'))return;
  setTemplateBusy(true);setNotice('');setError('');try{await api.delete(`${endpoint}/${selectedTemplate}`);setSelectedTemplate(null);await load();setNotice('Шаблон удалён');}catch(e){setError(message(e))}finally{setTemplateBusy(false)}
 }
 return <div className="border border-mk-border rounded-lg p-3 space-y-3">
  <h4 className="text-base font-semibold">{templatesOnly?'Шаблоны групп':'Группы пользователей MikroTik'} <span className="text-xs text-mk-mute">v0.9.3.7</span></h4>
  <p className="text-xs text-mk-mute" hidden={templatesOnly}>Шаг 1: выберите устройства в общем списке выше. Шаг 2: задайте операцию и нажмите синюю кнопку. Шаг 3: подтвердите готовые строки отчёта. Права, группы и перенос пользователей сначала проверяются в очереди, затем применяются только после подтверждения.</p>
  <div hidden={templatesOnly} className="space-y-2"><div className="flex flex-wrap gap-2 items-center"><button type="button" className="btn-secondary" disabled={busy||!count} onClick={onInventory}>Показать группы ({count})</button><span className="text-xs text-mk-mute">Группы, действующие права и локальные участники.</span></div></div>
  <div className="grid grid-cols-1 md:grid-cols-2 gap-3"><label className={templatesOnly?'hidden':'block text-sm'}>Операция<select className="input" value={mode} onChange={e=>setMode(e.target.value as Mode)}>{Object.entries(modes).map(([k,v])=><option value={k} key={k}>{v}</option>)}</select></label><label className="block text-sm">{mode==='move'?'Целевая группа':'Имя группы'}<input className="input" value={name} maxLength={32} onChange={e=>setName(e.target.value)}/></label></div>
  {mode==='move'&&<label className="block text-sm">Логин существующего пользователя<input className="input" maxLength={32} value={username} onChange={e=>setUsername(e.target.value)}/></label>}
  {needsRights&&<>
   <div><div className="text-xs text-mk-mute mb-2">Готовые наборы (заполняют имя и права, выбирают создание или дополнение)</div><div className="flex flex-wrap gap-2">{presets.map(p=><button type="button" className="btn-secondary" key={p.name} onClick={()=>{setSelectedTemplate(null);useTemplate(p)}}>{p.name}</button>)}</div></div>
   <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 rounded-md border border-mk-border p-3">{policies.map(p=><label key={p} className="flex gap-2 items-center font-mono text-xs"><input type="checkbox" checked={rights.includes(p)} onChange={e=>setRights(old=>e.target.checked?[...old,p]:old.filter(x=>x!==p))}/>{p}</label>)}</div>
   <p className="text-xs text-mk-mute">Выбрано разрешений: {rights.length} / {policies.length}. При удалении снимаются отмеченные права; при замене это итоговый список.</p>
   {rights.includes('policy')&&<p className="text-xs text-mk-warn">policy разрешает управление учётными записями; проверяйте назначение группы.</p>}
  </>}
  <details open={templatesOnly?true:undefined} className="rounded-md border border-mk-border p-3 space-y-2"><summary className="cursor-pointer font-medium">Сохранённые шаблоны групп ({templates.length})</summary><p className="text-xs text-mk-mute">Хранятся в PostgreSQL. Не применяются к оборудованию автоматически.</p><label className="block">Загрузить шаблон<select className="input" value={selectedTemplate??''} onChange={e=>{const id=Number(e.target.value)||null;setSelectedTemplate(id);const t=templates.find(x=>x.id===id);if(t)useTemplate(t)}}><option value="">Выберите шаблон</option>{templates.map(t=><option key={t.id} value={t.id}>{t.name} · {t.group_name}</option>)}</select></label><label className="block">Название шаблона<input className="input" maxLength={64} value={templateName} onChange={e=>setTemplateName(e.target.value)}/></label><div className="flex gap-2 flex-wrap"><button type="button" className="btn-secondary" disabled={templateBusy||!validGroup||!rights.length||!templateName.trim()||!['create','upsert','replace'].includes(mode)} onClick={()=>void saveTemplate()}>Сохранить шаблон</button><button type="button" className="btn-secondary" disabled={templateBusy||!selectedTemplate} onClick={()=>void removeTemplate()}>Удалить шаблон</button></div>{notice&&<p className="text-mk-ok text-xs">{notice}</p>}{error&&<p className="text-mk-err text-xs" role="alert">{error}</p>}</details>
  {!templatesOnly&&mode==='delete'&&<p className="text-mk-warn text-xs">Удаляются только пустые пользовательские группы. Действующие пользователи не удаляются.</p>}
  <p hidden={templatesOnly} className="text-xs text-mk-mute">Встроенные группы и группа AAA по умолчанию защищены. Обычные группы при отключённом RADIUS доступны для управления. Для группы контроллера разрешено только добавление прав; оно затрагивает всех её участников. Если включён RADIUS или фактические права изменились после проверки, операция блокируется.</p>
  <button type="button" className={templatesOnly?'hidden':'btn-primary'} disabled={busy||!valid||!count} onClick={()=>onPreview({group_name:name.trim(),group_mode:mode,group_user:username.trim(),group_policies:needsRights?rights:[]})}>{mode==='create'?'Создать группу':modes[mode]} ({count}) — проверить</button>
 </div>;
}
