import {useMemo,useState} from 'react';
import {Search} from 'lucide-react';
import {resolveDevicePreview} from '@/utils/devicePreview';
import {filterAutomationDevices,initialDeviceFilters,selectVisible,type AutomationDevice,type DeviceFilters} from '@/utils/automationDevices';
export default function AutomationDevicePicker({devices,selected,setSelected,disabled=false,showConnection=false,compact=false}:{devices:AutomationDevice[];selected:number[];setSelected:(ids:number[])=>void;disabled?:boolean;showConnection?:boolean;compact?:boolean}){
 const [filters,setFilters]=useState(initialDeviceFilters);
 const update=<K extends keyof DeviceFilters,>(key:K,value:DeviceFilters[K])=>setFilters(f=>({...f,[key]:value}));
 const visible=useMemo(()=>filterAutomationDevices(devices,selected,filters),[devices,selected,filters]);
 const sites=useMemo(()=>[...new Set(devices.map(d=>d.group_name?.trim()).filter((v):v is string=>Boolean(v)))].sort((a,b)=>a.localeCompare(b,'ru')),[devices]);
 const selectedSet=new Set(selected),visibleSelected=visible.filter(d=>selectedSet.has(d.id)).length,hidden=selected.length-visibleSelected;
 return <section className="rounded-lg border border-mk-border p-3 space-y-2" aria-label="Выбор оборудования">
  <div className="flex items-center flex-wrap gap-2"><h4 className="font-semibold text-sm">Оборудование</h4><span className="text-xs text-mk-mute">Выбрано <b>{selected.length}</b> из {devices.length} · Найдено {visible.length}</span></div>
  <fieldset disabled={disabled} className="space-y-2 min-w-0">
   <div className="relative"><Search size={15} className="absolute left-2 top-1/2 -translate-y-1/2 text-mk-mute pointer-events-none"/><input type="search" aria-label="Поиск оборудования" className="input !pl-8" placeholder="Имя, IP, модель, объект, комментарий…" value={filters.search} onChange={e=>update('search',e.target.value)}/></div>
   <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
    <select aria-label="Тип оборудования" className="input" value={filters.kind} onChange={e=>update('kind',e.target.value)}><option value="all">Все типы</option><option value="router">Роутеры</option><option value="switch">Свичи</option></select>
    <select aria-label="Объект" className="input" value={filters.site} onChange={e=>update('site',e.target.value)}><option value="all">Все объекты</option><option value="none">Без объекта</option>{sites.map(s=><option key={s} value={`site:${s}`}>{s}</option>)}</select>
    <select aria-label="Статус" className="input" value={filters.status} onChange={e=>update('status',e.target.value)}><option value="all">Все статусы</option><option value="up">Online</option><option value="down">Offline</option><option value="unknown">Неизвестно</option></select>
    <select aria-label="Сортировка" className="input" value={filters.sort} onChange={e=>update('sort',e.target.value)}><option value="name">По имени</option><option value="host">По IP</option><option value="model">По модели</option></select>
   </div>
   <div className="flex gap-2 items-center flex-wrap text-xs"><button className="btn-secondary" type="button" disabled={!visible.length} onClick={()=>setSelected(selectVisible(selected,visible))}>Все найденные ({visible.length})</button><button type="button" className="btn-secondary" disabled={!selected.length} onClick={()=>setSelected([])}>Снять выбор</button><label className="flex gap-1 items-center"><input type="checkbox" checked={filters.onlySelected} onChange={e=>update('onlySelected',e.target.checked)}/> Только выбранные</label><button type="button" className="text-mk-accent2" onClick={()=>setFilters(initialDeviceFilters)}>Сбросить фильтры</button></div>
   {hidden>0&&<div className="text-xs text-mk-warn flex flex-wrap items-center gap-2">Вне фильтра выбрано {hidden}; они тоже участвуют в операции.<button type="button" className="btn-secondary" onClick={()=>setSelected(visible.filter(d=>selectedSet.has(d.id)).map(d=>d.id))}>Снять скрытые</button></div>}
   <div className={`grid grid-cols-1 ${compact?'':'xl:grid-cols-2'} gap-1 max-h-48 overflow-auto`}>
   {visible.map(d=><label key={d.id} className="grid grid-cols-[auto_auto_1fr_auto] items-center gap-2 px-2 py-1 rounded border border-transparent hover:border-mk-border cursor-pointer min-w-0"><input type="checkbox" checked={selectedSet.has(d.id)} onChange={e=>setSelected(e.target.checked?[...selected,d.id]:selected.filter(id=>id!==d.id))}/><img src={`${import.meta.env.BASE_URL}device-previews/${resolveDevicePreview(d.model,d.kind)}.svg`} alt="" width={52} height={24} className="object-contain w-12 h-6" loading="lazy"/><span className="min-w-0"><span className="block text-sm break-words">{d.identity||d.name}</span><span className="block text-xs text-mk-mute break-words">{[d.model,d.group_name,showConnection?d.username:undefined].filter(Boolean).join(' · ')}</span></span><span className="text-xs text-right whitespace-nowrap"><span className={d.status==='up'?'text-mk-ok':d.status==='down'?'text-mk-err':'text-mk-mute'} title={d.status==='up'?'Online':d.status==='down'?'Offline':'Неизвестно'}>● </span>{d.host}{showConnection&&d.port?`:${d.port}${d.use_tls?' TLS':''}`:''}</span></label>)}
   {!visible.length&&<p className="text-xs text-mk-mute p-3">{devices.length?'По фильтрам ничего не найдено.':'Нет загруженных устройств.'}</p>}
   </div>
  </fieldset>
 </section>
}
