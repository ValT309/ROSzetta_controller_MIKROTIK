import {useEffect,useRef,useState} from 'react';
import {api,type Device,type DeviceBackup,type Firmware} from '@/api/client';
import {compareVersions} from '@/utils/version';
import {GroupSelect} from '@/components/DeviceGroups';

type Mode='backup'|'check'|'internet'|'repository'|'routerboot'|'reboot'|'group';
type Live={version:string|null;architecture:string|null;free_disk:number|string|null;uptime_seconds:number|null;packages:string[];routerboard:boolean|string|null;current_firmware:string|null;upgrade_firmware:string|null};
type Entry={id:number;name:string;state:string};
const ver=(v:unknown)=>String(v||'').trim().match(/^\d+(?:\.\d+){1,2}(?=\s|$)/)?.[0]||'';
const arch=(v:unknown)=>String(v||'').toLowerCase().replace(/[-_]/g,'');
const name=(d:Device)=>d.identity||d.name;
const sleep=(ms:number)=>new Promise<void>(r=>setTimeout(r,ms));
const timeout={timeout:120000};
const errorText=(e:unknown)=>{const x=e as {response?:{data?:{detail?:unknown}};message?:string};return typeof x?.response?.data?.detail==='string'?x.response.data.detail:x?.message||'Ошибка API';};
const modes:{id:Mode;label:string}[]=[{id:'backup',label:'Резервное копирование'},{id:'check',label:'Проверить обновления RouterOS'},{id:'internet',label:'Обновить RouterOS из интернета'},{id:'repository',label:'Обновить RouterOS из репозитория'},{id:'routerboot',label:'Обновить RouterBOOT'},{id:'reboot',label:'Перезагрузить'},{id:'group',label:'Изменить группу'}];
const read=(id:number)=>api.get<Live>(`/devices/${id}/maintenance-state`,{timeout:45000}).then(r=>r.data);
async function backup(id:number){
 const before=await api.get<DeviceBackup[]>(`/devices/${id}/backups`);
 const old=new Set(before.data.map(b=>b.id));
 const {data}=await api.post<DeviceBackup[]>(`/devices/${id}/backups`,null,timeout);
 const fresh=data.filter(b=>!old.has(b.id)&&b.size>0);
 if(!fresh.some(b=>b.fmt==='binary'&&fresh.some(t=>t.fmt==='text'&&t.filename.replace(/\.rsc$/,'')===b.filename.replace(/\.backup$/,''))))throw Error('Не подтверждена новая пара .backup/.rsc');
}
async function waitForBoot(id:number,before:Live,expected:string|null,boot:boolean,stop:()=>boolean){
 // Do not accept the old session immediately after sending the reboot.
 const started=Date.now(); let disconnected=false;
 while(Date.now()-started<480000){
  if(stop())throw Error('Остановлено: состояние текущего устройства необходимо проверить вручную');
  await sleep(10000);
  let after:Live;
  try{after=await read(id);}catch{disconnected=true;continue;}
  const elapsed=(Date.now()-started)/1000;
  const restarted=after.uptime_seconds!==null&&before.uptime_seconds!==null&&(after.uptime_seconds<before.uptime_seconds|| (disconnected&&after.uptime_seconds<=elapsed+15));
  if(!restarted)continue;
  if(expected&&(boot?after.current_firmware!==expected:ver(after.version)!==expected))throw Error('После перезагрузки целевая версия не подтверждена');
  return;
 }
 throw Error('Не подтверждена перезагрузка за отведённое время');
}
export default function DeviceBatch({devices,onClose}:{devices:Device[];onClose:()=>void}){
 const [mode,setMode]=useState<Mode>('backup'),[channel,setChannel]=useState('long-term'),[target,setTarget]=useState(''),[firmware,setFirmware]=useState<Firmware[]>([]),[group,setGroup]=useState(''),[busy,setBusy]=useState(false),[entries,setEntries]=useState<Entry[]>([]),[message,setMessage]=useState(''),[lab,setLab]=useState(false),[attempted,setAttempted]=useState(false);
 const stop=useRef(false), running=useRef(false);
 useEffect(()=>{api.get<Firmware[]>('/firmware').then(r=>setFirmware(r.data)).catch(()=>setMessage('Не удалось загрузить репозиторий прошивок'));return()=>{stop.current=true;};},[]);
 useEffect(()=>{if(!busy)return;const warn=(e:BeforeUnloadEvent)=>{e.preventDefault();e.returnValue='';};window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn);},[busy]);
 const versions=Array.from(new Set(firmware.filter(f=>f.channel===channel&&ver(f.version)).map(f=>ver(f.version)))).sort((a,b)=>compareVersions(b,a));
 const log=(id:number,state:string)=>setEntries(old=>old.map(x=>x.id===id?{...x,state}:x));
 const run=async()=>{
  if(running.current||!devices.length||attempted)return;
  if(['internet','repository','routerboot','reboot'].includes(mode)&&!lab)return;
  if(mode==='repository'&&!target)return;
  if(!window.confirm(`Операция: ${modes.find(m=>m.id===mode)?.label}. Устройства: ${devices.length}. ${['internet','repository','routerboot','reboot'].includes(mode)?'Возможен перерыв связи. Выполнять только в согласованное окно. ':''}Начать последовательную очередь?`))return;
  running.current=true;stop.current=false;setAttempted(true);setBusy(true);setMessage('');setEntries(devices.map(d=>({id:d.id,name:name(d),state:'Ожидает'})));
  try{
   for(const d of devices){
    if(stop.current)break;
    try{
     log(d.id,'Проверка');
     if(mode==='group'){await api.patch(`/devices/${d.id}`,{group_name:group||null});log(d.id,'Группа изменена');continue;}
     if(mode==='backup'){await backup(d.id);log(d.id,'Новая пара файлов получена');continue;}
     const live=await read(d.id);
     if(!ver(live.version)||live.uptime_seconds===null)throw Error('Не подтверждены версия RouterOS и uptime');
     if(mode==='check'||mode==='internet'){
      const {data}=await api.post(`/devices/${d.id}/upgrade/internet`,null,{...timeout,params:{channel,install:false}});
      const info=data?.info||{};const latest=ver(info['latest-version']);const installed=ver(info['installed-version']);
      if(mode==='check'){if(!latest||info.channel!==channel)throw Error('Канал или доступная версия не подтверждены');log(d.id,`Установлено ${installed||ver(live.version)}; доступно ${latest}`);continue;}
      if(info.channel!==channel||!latest||installed!==ver(live.version))throw Error('Канал или версии не подтверждены');
      if(compareVersions(latest,installed)<=0){log(d.id,'Обновление не требуется');continue;}
      if(!String(info.status||'').toLowerCase().includes('new version is available'))throw Error('RouterOS не подтвердил наличие обновления');
      if(!Number.isFinite(Number(live.free_disk))||Number(live.free_disk)<=0)throw Error('Не подтверждено свободное место');
      log(d.id,'Создание копии');await backup(d.id);if(stop.current)break;
      log(d.id,`Установка ${latest}`);
      await api.post(`/devices/${d.id}/upgrade/internet`,null,{...timeout,params:{channel,install:true,expected_version:latest}});
      log(d.id,'Ожидание перезагрузки');await waitForBoot(d.id,live,latest,false,()=>stop.current);
     }else if(mode==='repository'){
      const candidates=firmware.filter(f=>f.channel===channel&&ver(f.version)===target&&arch(f.architecture)===arch(live.architecture)&&/^routeros[-_].*\.npk$/i.test(f.name));
      if(!live.architecture||candidates.length!==1)throw Error('Нет однозначного основного NPK для архитектуры устройства');
      const f=candidates[0];if(compareVersions(target,ver(live.version))<=0){log(d.id,'Пропущено: версия не новее');continue;}
      if(!Array.isArray(live.packages)||live.packages.length!==1||live.packages[0]!=='routeros')throw Error('Есть дополнительные или неизвестные пакеты: используйте обновление из интернета');
      if(!f.size||!Number.isFinite(Number(live.free_disk))||Number(live.free_disk)<f.size+2*1024*1024)throw Error('Недостаточно подтверждённого места для NPK');
      log(d.id,'Создание копии');await backup(d.id);if(stop.current)break;
      log(d.id,`Установка ${target}`);await api.post(`/devices/${d.id}/upgrade/local`,null,{...timeout,params:{firmware_id:f.id,reboot:true}});
      log(d.id,'Ожидание перезагрузки');await waitForBoot(d.id,live,target,false,()=>stop.current);
     }else if(mode==='routerboot'){
      const expected=live.upgrade_firmware;
      if(!expected||!live.current_firmware||!['true','yes'].includes(String(live.routerboard).toLowerCase()))throw Error('RouterBOOT недоступен');
      if(compareVersions(expected,live.current_firmware)<=0){log(d.id,'Обновление RouterBOOT не требуется');continue;}
      log(d.id,'Создание копии');await backup(d.id);if(stop.current)break;
      log(d.id,'Подготовка RouterBOOT');const {data}=await api.post(`/devices/${d.id}/maintenance-routerboot`,null,{...timeout,params:{expected}});
      if(!data?.staged)throw Error('Подготовка RouterBOOT не подтверждена');if(stop.current)throw Error('RouterBOOT подготовлен, перезагрузка не выполнена');
      await api.post(`/devices/${d.id}/reboot`,null,timeout);log(d.id,'Ожидание RouterBOOT');await waitForBoot(d.id,live,expected,true,()=>stop.current);
     }else{
      log(d.id,'Создание копии');await backup(d.id);if(stop.current)break;
      await api.post(`/devices/${d.id}/reboot`,null,timeout);log(d.id,'Ожидание перезагрузки');await waitForBoot(d.id,live,null,false,()=>stop.current);
     }
     log(d.id,'Версия и/или перезагрузка подтверждены через API');
    }catch(e){log(d.id,`СТОП: ${errorText(e)}. Не повторяйте вслепую.`);setMessage('Очередь остановлена. Проверьте устройство перед повторной попыткой.');stop.current=true;break;}
   }
   if(!stop.current)setMessage('Очередь завершена');else {setMessage('Очередь остановлена. Проверьте последнее устройство; не повторяйте операцию вслепую.');setEntries(old=>old.map(x=>x.state==='Ожидает'?{...x,state:'Не запущено'}:x));}
  }finally{running.current=false;setBusy(false);}
 };
 return <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4" role="dialog" aria-modal="true"><div className="card w-full max-w-3xl max-h-[90vh] overflow-auto space-y-3"><h3 className="text-base font-semibold">Массовые операции ({devices.length})</h3><p className="text-xs text-mk-warn">Последовательно, с остановкой при ошибке. Не закрывайте вкладку. Не запускайте другую очередь одновременно. Проверка канала RouterOS меняет настройку канала. Резервная копия не гарантирует восстановление.</p><fieldset disabled={busy||attempted} className="space-y-2"><select className="input" value={mode} onChange={e=>setMode(e.target.value as Mode)}>{modes.map(m=><option key={m.id} value={m.id}>{m.label}</option>)}</select>{['check','internet','repository'].includes(mode)&&<select className="input" value={channel} onChange={e=>{setChannel(e.target.value);setTarget('');}}><option value="long-term">long-term</option><option value="stable">stable</option></select>}{mode==='repository'&&<select className="input" value={target} onChange={e=>setTarget(e.target.value)}><option value="">Выберите версию репозитория</option>{versions.map(v=><option key={v}>{v}</option>)}</select>}{mode==='group'&&<GroupSelect value={group} onChange={setGroup}/>}<p className="text-xs text-mk-warn">Изменение прошивки и перезагрузка — экспериментальный режим, сначала проверьте на отдельном устройстве.</p>{['internet','repository','routerboot','reboot'].includes(mode)&&<label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={lab} onChange={e=>setLab(e.target.checked)}/> Выбраны только тестовые устройства; разрешаю перезагрузки</label>}</fieldset><div className="max-h-64 overflow-auto border border-mk-border rounded p-2 text-xs space-y-1">{(entries.length?entries:devices.map(d=>({id:d.id,name:name(d),state:d.host}))).map(x=><div key={x.id} className="flex flex-wrap gap-2 justify-between"><span>{x.name}</span><span className={x.state.startsWith('СТОП')?'text-mk-err':'text-mk-mute'}>{x.state}</span></div>)}</div>{message&&<p className="text-sm" role="status">{message}</p>}<div className="flex justify-end gap-2"><button className="btn-secondary" disabled={busy} onClick={onClose}>Закрыть</button>{busy?<button className="btn-secondary" onClick={()=>{stop.current=true;setMessage('Остановка: текущий запрос уже может выполняться');}}>Остановить очередь</button>:<button className="btn-primary" disabled={attempted||(mode==='repository'&&!target)||(['internet','repository','routerboot','reboot'].includes(mode)&&!lab)} onClick={()=>void run()}>Запустить</button>}</div></div></div>;
}
