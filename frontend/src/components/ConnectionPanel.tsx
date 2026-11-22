import { useEffect, useRef, useState } from 'react';
import { KeyRound } from 'lucide-react';
import { api, Device } from '@/api/client';
import AutomationDevicePicker from './AutomationDevicePicker';
import ManagementBatch from './ManagementBatch';
import type {TlsCache} from '@/utils/tlsWizard';
import {useSearchParams} from 'react-router-dom';

type Job={id:number;action:string;state:string;entries:{id:number;name:string;host:string;state:string;detail?:string}[]};
const endpoint='/devices/stage2';
const TRANSPORTS = [
  { key: 'keep', label: 'Не менять (как сейчас у каждого устройства)' },
  { key: 'api', label: 'api, порт 8728 (без шифрования)' },
  { key: 'api-ssl', label: 'api-ssl, порт 8729 (TLS, нужен сертификат на роутере)' },
];

export default function ConnectionPanel() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [username, setUsername] = useState('');
  const [pwd, setPwd] = useState('');
  const [pwd2, setPwd2] = useState('');
  const [transport, setTransport] = useState('keep');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [params]=useSearchParams();
  const [jobId,setJobId]=useState<number|null>(Number(params.get('managementJob'))||null);
  const [jobs,setJobs]=useState<Job[]>([]);
  const [tlsReports,setTlsReports]=useState<Job[]>([]);
  const restored=useRef<number|null>(null);
  const requestedId=Number(params.get('managementJob'))||null;
  const [sslFilter,setSslFilter]=useState('all');
  const [ssl,setSsl]=useState<TlsCache>({});
  const lock=useRef(false);
  const request=useRef<{key:string;id:string}|null>(null);
  const job=jobs.find(j=>j.id===jobId);
  const active=job&&['queued','running'].includes(job.state);
  const shown=devices.filter(d=>sslFilter==='all'||(sslFilter==='pinned'?d.use_tls&&Boolean(d.tls_fingerprint):sslFilter==='unprepared'?!d.use_tls:sslFilter==='recovery'?d.use_tls&&!d.tls_fingerprint:(ssl[String(d.id)]?.status||'unknown')===sslFilter));
  const chooseFilter=(value:string)=>{setSslFilter(value);setSelected([])};


  const load = () =>
    api.get<Device[]>('/devices').then((r) => setDevices(r.data)).catch(() => {});

  useEffect(() => { load(); }, []);
  useEffect(()=>{setJobId(Number(params.get('managementJob'))||null)},[params]);
  useEffect(()=>{let live=true,loading=false;async function poll(){if(loading)return;loading=true;try{const [j,c,d]=await Promise.all([api.get<Job[]>(`${endpoint}/jobs`),api.get<TlsCache>(`${endpoint}/ssl-status`),api.get<Device[]>('/devices')]);if(live){setJobs(j.data.filter(x=>x.action.startsWith('connection-')));setTlsReports(j.data.filter(x=>x.action==='tls-scan'||x.action==='tls-switch'));setSsl(c.data);setDevices(d.data);}}catch{}finally{loading=false}}void poll();const t=window.setInterval(poll,5000);return()=>{live=false;clearInterval(t)}},[]);

  useEffect(()=>{if(!requestedId){restored.current=null;return}if(restored.current===requestedId)return;const report=tlsReports.find(j=>j.id===requestedId);if(!report||!devices.length)return;const ids=new Set(devices.map(d=>d.id));setSelected(report.entries.map(e=>e.id).filter(id=>ids.has(id)));setSslFilter('all');restored.current=requestedId},[requestedId,tlsReports,devices]);

  const run = async (apply: boolean) => {
    setError(null);
    if(lock.current)return;
    if (active) {setError('Дождитесь окончания текущей задачи или остановите её.');return;}
    if (!selected.length) { setError('Выберите хотя бы одно устройство'); return; }
    if (!/^[A-Za-z0-9_.-]{1,32}$/.test(username.trim())) {
      setError('Логин: 1-32 символа, латиница, цифры, _ . -');
      return;
    }
    if (!pwd) { setError('Введите пароль'); return; }
    if (pwd !== pwd2) { setError('Пароли не совпадают'); return; }
    if (apply && !window.confirm(
      `Сохранить логин «${username.trim()}» и новый пароль для подключения контроллера ` +
      `к устройствам: ${selected.length}?\n\nСохраняется только там, где вход прошёл успешно.`,
    )) return;
    const allowPlain=transport==='api'||(transport==='keep'&&devices.some(d=>selected.includes(d.id)&&!d.use_tls));
    if(allowPlain&&!window.confirm('Часть устройств использует обычный API. Подтвердите передачу пароля без TLS.'))return;
    const key=JSON.stringify([[...selected].sort((a,b)=>a-b),username.trim(),transport,apply]);
    const id=request.current?.key===key?request.current.id:(typeof crypto.randomUUID==='function'?crypto.randomUUID():Array.from(crypto.getRandomValues(new Uint8Array(16)),x=>x.toString(16).padStart(2,'0')).join(''));
    request.current={key,id};lock.current=true;setBusy(true);
    try {
      const r=await api.post<Job>(`${endpoint}/connection-jobs`,{ids:selected,username:username.trim(),password:pwd,transport,apply,confirmed:apply,allow_plain:allowPlain,request_id:id});
      setJobs(old=>[r.data,...old.filter(x=>x.id!==r.data.id)]);setJobId(r.data.id);request.current=null;setPwd('');setPwd2('');
    } catch (ex: any) {
      const d=ex?.response?.data?.detail;
      if(ex?.response?.status>=400&&ex?.response?.status<500)request.current=null;
      setError(typeof d==='string'?d:'Запрос не подтверждён. Проверьте центр задач перед повтором; повтор с теми же параметрами возвращает исходную задачу.');
    } finally {lock.current=false;setBusy(false);}

  };

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <KeyRound size={14} className="text-mk-accent2" />
        <h3 className="text-sm font-semibold">Подключение контроллера к устройствам</h3>
      </div>
      <p className="text-xs text-mk-mute">
        Меняет логин и пароль, под которыми контроллер входит на выбранные устройства. Сначала выполняется
        вход с новыми данными, и только если он прошёл, они сохраняются. Пользователь должен уже существовать
        на устройствах (вкладка «Пользователи»). Запуск создаёт серверную задачу; страницу можно закрыть.
      </p>

      <label className="block text-xs text-mk-mute">Фильтр SSL<select className="input" value={sslFilter} onChange={e=>chooseFilter(e.target.value)}><option value="all">Все устройства</option><option value="pinned">TLS с закреплённым отпечатком</option><option value="unprepared">Обычный API (нужна подготовка)</option><option value="recovery">TLS без закреплённого отпечатка</option><option value="secure">API-SSL проверен (кэш)</option><option value="issued">Сертификат выпущен</option><option value="attention">Требует проверки</option><option value="error">Ошибка сертификата</option><option value="none">Нет сертификата</option><option value="unknown">Не проверено</option></select></label>
      <AutomationDevicePicker devices={shown} selected={selected} setSelected={setSelected} disabled={busy} showConnection/>

      <ManagementBatch devices={devices.filter(d=>selected.includes(d.id))} scope="tls" sslCache={ssl} connectionBusy={busy||!!active} connectionStep={<div className="border border-mk-border p-3 rounded space-y-3"><h4 className="font-semibold">Учётные данные подключения (необязательно)</h4>      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <div>
          <label className="text-xs text-mk-mute">Новый логин</label>
          <input className="input" autoComplete="off" value={username} onChange={(e) => {request.current=null;setUsername(e.target.value)}} />
        </div>
        <div>
          <label className="text-xs text-mk-mute">Пароль</label>
          <input
            className="input" type="password" autoComplete="new-password" spellCheck={false}
            name="roszetta-conn-password" value={pwd} onChange={(e) => {request.current=null;setPwd(e.target.value)}}
          />
        </div>
        <div>
          <label className="text-xs text-mk-mute">Повторите пароль</label>
          <input
            className="input" type="password" autoComplete="new-password" spellCheck={false}
            name="roszetta-conn-password2" value={pwd2} onChange={(e) => setPwd2(e.target.value)}
          />
        </div>
      </div>

      <div>
        <label className="text-xs text-mk-mute">Тип подключения</label>
        <select className="input" value={transport} onChange={(e) => setTransport(e.target.value)}>
          {TRANSPORTS.map((t) => <option key={t.key} value={t.key}>{t.label}</option>)}
        </select>
      </div>

      <div className="flex gap-2">
        <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={busy||!!active||!selected.length||!username.trim()||!pwd||pwd!==pwd2} onClick={() => run(false)}>
          Только проверить
        </button>
        <button type="button" className="btn-primary !text-xs" disabled={busy||!!active||!selected.length||!username.trim()||!pwd||pwd!==pwd2} onClick={() => run(true)}>
          {busy ? 'Выполняем…' : 'Проверить и сохранить подключение'}
        </button>
      </div>

      {(!selected.length||!username.trim()||!pwd||pwd!==pwd2||active||busy)&&<p className="text-xs text-mk-mute">{active||busy?'Дождитесь завершения задачи подключения.':!selected.length?'Выберите оборудование выше.':!username.trim()||!pwd?'Для изменения учётных данных заполните логин и пароль.': 'Пароли не совпадают.'}</p>}
      {error && <div className="text-sm text-mk-err">{error}</div>}

      <label className="block text-xs text-mk-mute">Очередь подключения<select className="input" value={jobId??''} onChange={e=>setJobId(Number(e.target.value)||null)}><option value="">Нет выбранной задачи</option>{jobs.map(j=><option key={j.id} value={j.id}>#{j.id} · {j.action==='connection-save'?'Сохранение':'Проверка'} · {j.state}</option>)}</select></label>
      {job&&<div className="space-y-2"><b>Задача #{job.id}: {job.entries.filter(e=>!['pending','running'].includes(e.state)).length}/{job.entries.length}</b>{active&&<button className="btn-secondary ml-2" type="button" onClick={()=>api.post(`${endpoint}/jobs/${job.id}/stop`).catch(()=>setError('Остановка не подтверждена'))}>Остановить после текущего</button>}<div className="max-h-64 overflow-auto">{job.entries.map(e=><div key={e.id} className="p-2 border-t border-mk-border text-xs"><b>{e.name}</b> · {e.host} · <span className={e.state==='done'?'text-mk-ok':e.state==='failed'||e.state==='unknown'?'text-mk-err':'text-mk-mute'}>{({done:'Успешно',failed:'Ошибка',unknown:'Не подтверждено',pending:'Ожидает',running:'Выполняется'} as Record<string,string>)[e.state]||e.state}</span><p>{e.detail}</p></div>)}</div></div>}

      </div>}/>
    </div>
  );
}
