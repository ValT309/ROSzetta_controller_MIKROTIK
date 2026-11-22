import { FormEvent, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { UserPlus, Lock, Trash2 } from 'lucide-react';
import { api, type Device } from '@/api/client';
import ManagementBatch, { type AccountRetry } from './ManagementBatch';
import AutomationDevicePicker from './AutomationDevicePicker';

type Mode = 'add' | 'password' | 'delete';
type Section = 'users' | 'groups' | 'audit' | 'templates';
const sections: {id:Section;label:string;description:string}[] = [{id:'users',label:'Пользователи',description:'Создание, смена пароля и удаление учётных записей.'},{id:'groups',label:'Группы',description:'Просмотр, создание и изменение прав групп RouterOS.'},{id:'audit',label:'Аудит',description:'Проверка прав контроллера и восстановление доверия TLS.'},{id:'templates',label:'Шаблоны',description:'Наборы прав, сохранённые на контроллере. Не изменяют устройства.'}];

type DevRow = Device;

const MODES: { key: Mode; label: string }[] = [
  { key: 'add', label: 'Добавить' },
  { key: 'password', label: 'Сменить пароль' },
  { key: 'delete', label: 'Удалить' },
];

export default function DeviceUsersPanel() {
  const location=useLocation();
  const navigate=useNavigate();
  const requestedSection=new URLSearchParams(location.search).get('managementTab');
  const [section,setSection]=useState<Section>(requestedSection==='groups'||requestedSection==='audit'?requestedSection:'users');
  useEffect(()=>{if(requestedSection==='groups'||requestedSection==='audit'||requestedSection==='users'||requestedSection==='templates')setSection(requestedSection)},[location.key,requestedSection]);
  const [mode, setMode] = useState<Mode>('add');
  const [deviceLoadError,setDeviceLoadError]=useState('');
  const [devices, setDevices] = useState<DevRow[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [username, setUsername] = useState('');
  const [group, setGroup] = useState('read');
  const [groups, setGroups] = useState<string[]>(['read', 'write', 'full']);
  const [groupsBusy, setGroupsBusy] = useState(false);
  const [notice,setNotice]=useState('');
  const [retryJob,setRetryJob]=useState<number|null>(null);
  const [allowPlain,setAllowPlain]=useState(false);
  const submitting=useRef(false);
  const [address, setAddress] = useState('');
  const [updateExisting, setUpdateExisting] = useState(false);

  const [modal, setModal] = useState(false);
  const [pwd, setPwd] = useState('');
  const [pwd2, setPwd2] = useState('');
  const [confirmText, setConfirmText] = useState('');
  const [modalErr, setModalErr] = useState<string | null>(null);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.get<DevRow[]>('/devices').then((r) => setDevices(r.data)).catch(() => setDeviceLoadError('Не удалось загрузить устройства. Обновите страницу.'));
  }, []);

  const chosen = devices.filter((d) => selected.includes(d.id));
  const plain = chosen.filter((d) => d.use_tls === false);
  const login = username.trim();


  const changeMode = (m: Mode) => {
    setMode(m);
    setError(null);
    setRetryJob(null);
    setNotice('');
  };

  const closeModal = () => {
    setModal(false);
    setPwd('');
    setPwd2('');
    setConfirmText('');
    setModalErr(null);
    setAllowPlain(false);
  };

  const requestId=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');
  const showJob=(id:number)=>navigate({pathname:location.pathname,search:`?managementTab=users&managementJob=${id}`,hash:'#users'},{replace:true});
  const loadGroups = async () => {
    if (submitting.current||!selected.length) return;
    submitting.current=true;setGroupsBusy(true);setError(null);setNotice('');
    try {
      const r=await api.post<{id:number}>('/devices/stage2/user-jobs',{action:'user-groups',ids:selected,request_id:requestId()});
      showJob(r.data.id);setNotice(`Задача #${r.data.id}: группы будут загружены из отчёта после завершения опроса.`);
    } catch (ex:any) {
      const d=ex?.response?.data?.detail;
      setError(typeof d==='string'?d:'Постановка задачи не подтверждена. Проверьте центр задач перед повтором.');
    } finally {submitting.current=false;setGroupsBusy(false);}
  };
  const onGroups=(names:string[],failed:number)=>{
    if(names.length)setGroups(names);
    setNotice(`Групп найдено: ${names.length}${failed?`; не удалось опросить устройств: ${failed}`:''}. Наличие группы проверяется отдельно на каждом устройстве.`);
  };
  const retryUsers=(r:AccountRetry)=>{
    setMode(r.action==='user-add'?'add':r.action==='user-password'?'password':'delete');
    setUsername(r.spec.username);setGroup(r.spec.group||'read');setAddress(r.spec.address||'');
    setUpdateExisting(Boolean(r.spec.update_existing));setSelected(r.ids);setRetryJob(r.jobId);
    setError(null);setNotice('Выбраны только устройства без подтверждённой попытки записи. Для повтора заново введите пароль или подтвердите удаление.');
    setModal(false);setPwd('');setPwd2('');setConfirmText('');setModalErr(null);setAllowPlain(false);
  };

  const start = (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!selected.length) { setError('Выберите хотя бы одно устройство'); return; }
    if (mode==='add'&&!/^[A-Za-z0-9_.-]{1,32}$/.test(group.trim())) {setError('Укажите корректное имя группы');return;}
    if (!/^[A-Za-z0-9_.-]{1,32}$/.test(login)) {
      setError('Логин: 1-32 символа, латиница, цифры, _ . -');
      return;
    }
    setModal(true);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (mode === 'delete') {
      if (confirmText.trim() !== login) { setModalErr('Введите логин точно так же для подтверждения'); return; }
    } else {
      if (pwd.length < 8 || pwd.length > 128) { setModalErr('Пароль: 8–128 символов'); return; }
      if (pwd !== pwd2) { setModalErr('Пароли не совпадают'); return; }
    }
    if (submitting.current) return;
    if (mode!=='delete'&&plain.length&&!allowPlain) {setModalErr('Подтвердите передачу пароля по обычному API или снимите выбор этих устройств');return;}
    submitting.current=true;setBusy(true);setError(null);setNotice('');
    try {
      const action=mode==='add'?'user-add':mode==='password'?'user-password':'user-delete';
      const r=await api.post<{id:number}>('/devices/stage2/user-jobs',{
        action,ids:selected,username:login,confirmed:true,request_id:requestId(),
        ...(mode!=='delete'?{password:pwd,allow_plain:allowPlain}:{}),
        ...(mode==='add'?{group:group.trim(),address:address.trim(),update_existing:updateExisting}:{}),
        ...(retryJob!==null?{retry_job:retryJob}:{})
      });
      setRetryJob(null);showJob(r.data.id);setNotice(`Задача #${r.data.id} принята в серверную очередь. Следите за результатами в центре задач; вкладку можно закрыть.`);
    } catch (ex:any) {
      const d=ex?.response?.data?.detail;
      setError(typeof d==='string'?d:'Постановка задачи не подтверждена. Проверьте центр задач перед повтором — запрос мог быть принят сервером.');
    } finally {
      submitting.current=false;setBusy(false);closeModal();
    }
  };

  const needsPassword = mode !== 'delete';
  const startLabel = mode === 'add' ? 'Добавить пользователя' : mode === 'password' ? 'Сменить пароль' : 'Удалить пользователя';

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <UserPlus size={14} className="text-mk-accent2" />
        <h3 className="text-sm font-semibold">Пользователи на устройствах</h3>
      </div>

      <nav className="flex flex-wrap gap-2 border-b border-mk-border pb-2" aria-label="Разделы управления доступом">{sections.map(t=><button key={t.id} type="button" className={section===t.id?'btn-primary':'btn-secondary'} disabled={busy||modal||groupsBusy} aria-pressed={section===t.id} onClick={()=>setSection(t.id)}>{t.label}</button>)}</nav>
      <p className="text-sm text-mk-mute">{sections.find(t=>t.id===section)?.description}</p>
      {deviceLoadError&&<p role="alert" className="text-mk-err">{deviceLoadError}</p>}
      <div hidden={section==='templates'}><AutomationDevicePicker devices={devices} selected={selected} setSelected={setSelected} disabled={busy||modal||groupsBusy}/></div>
      
      <div hidden={section!=='users'} className="space-y-3">
      <div className="flex gap-1">
        {MODES.map((m) => (
          <button
            key={m.key}
            type="button"
            onClick={() => changeMode(m.key)}
            className={`text-xs px-3 py-1.5 rounded border ${
              mode === m.key ? 'border-mk-accent2 text-mk-accent2' : 'border-mk-border text-mk-mute hover:bg-white/10'
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>

      {retryJob!==null&&<div className="border border-mk-border rounded p-2 flex flex-wrap gap-2 items-center text-xs"><span>Повтор задачи #{retryJob}: исходные параметры сохранены. Неопределённые записи исключены.</span><button type="button" className="btn-secondary" onClick={()=>setRetryJob(null)}>Отменить режим повтора</button></div>}
      <form onSubmit={start} className="space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
          <div>
            <label className="text-xs text-mk-mute">Логин</label>
            <input className="input" value={username} disabled={retryJob!==null||busy} onChange={(e) => setUsername(e.target.value)} required />
          </div>
          {mode === 'add' && (
            <>
              <div>
                <label className="text-xs text-mk-mute">Группа на устройстве</label>
                <select
                  className="input"
                  disabled={retryJob!==null||busy}
                  value={groups.includes(group) ? group : '__custom'}
                  onChange={(e) => setGroup(e.target.value === '__custom' ? '' : e.target.value)}
                >
                  {groups.map((g) => <option key={g} value={g}>{g}</option>)}
                  <option value="__custom">другая…</option>
                </select>
                {!groups.includes(group) && (
                  <input
                    className="input mt-1" placeholder="имя группы" required
                    value={group} disabled={retryJob!==null||busy} onChange={(e) => setGroup(e.target.value)}
                  />
                )}
                <button
                  type="button" className="btn-secondary mt-1"
                  disabled={groupsBusy||busy||!selected.length||retryJob!==null} onClick={loadGroups}
                >
                  {groupsBusy ? 'Загрузка…' : 'Загрузить группы с выбранных устройств'}
                </button>
              </div>
              <div>
                <label className="text-xs text-mk-mute">Разрешённые адреса (необязательно)</label>
                <input className="input" placeholder="10.110.0.109/32" value={address} disabled={retryJob!==null||busy} onChange={(e) => setAddress(e.target.value)} />
              </div>
            </>
          )}
        </div>


        {mode === 'add' && (
          <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer">
            <input type="checkbox" checked={updateExisting} disabled={retryJob!==null||busy} onChange={(e) => setUpdateExisting(e.target.checked)} />
            Если пользователь уже есть, обновить пароль и группу (учётная запись текущего подключения ROSzetta защищена)
          </label>
        )}
        {mode === 'password' && (
          <p className="text-xs text-mk-mute">
            Пароль меняется только там, где пользователь уже есть; группа и адреса не затрагиваются.
          </p>
        )}
        {mode === 'delete' && (
          <p className="text-xs text-mk-mute">
            Учётную запись самого контроллера и последнего пользователя группы full удалить нельзя.
          </p>
        )}

        <button className={mode === 'delete' ? 'btn-primary !text-xs' : 'btn-primary !text-xs'} disabled={busy||groupsBusy||!selected.length}>
          {startLabel} ({selected.length})
        </button>
      </form>

      {error && <div role="alert" className="text-sm text-mk-err">{error}</div>}
      {notice&&<p role="status" className="text-sm text-mk-ok">{notice}</p>}

      </div>
      <ManagementBatch rightsOnly devices={chosen} scope={section} onAccountGroups={onGroups} onRetryUsers={retryUsers}/>
      {modal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={()=>{if(!busy)closeModal()}}>
          <form
            onSubmit={submit}
            onClick={(e) => e.stopPropagation()}
            className="card w-full max-w-sm space-y-3"
            autoComplete="off"
          >
            <div className="flex items-center gap-2">
              {needsPassword ? <Lock size={14} className="text-mk-accent2" /> : <Trash2 size={14} className="text-mk-err" />}
              <h3 className="text-sm font-semibold">
                {mode === 'delete' ? `Удалить «${login}»` : `Пароль для «${login}»`}
              </h3>
            </div>

            {needsPassword ? (
              <>
                <p className="text-xs text-mk-mute">
                  Устройств: {selected.length}
                  {mode === 'add' ? `, группа «${group.trim()}»` : ''}. Пароль временно хранится в зашифрованном Vault секрете задачи (до завершения, остановки или 24 часов). В историю и отчёты не попадает.
                </p>
                {plain.length > 0 && (
                  <label className="flex gap-2 items-start text-xs text-mk-err"><input type="checkbox" checked={allowPlain} onChange={e=>setAllowPlain(e.target.checked)}/> Подтверждаю: для {plain.length} устройств используется API без TLS, пароль будет передан по сети открытым текстом.</label>
                )}
                <div>
                  <label className="text-xs text-mk-mute">Пароль (8–128 символов)</label>
                  <input
                    className="input" type="password" name="roszetta-device-user-password"
                    autoComplete="new-password" spellCheck={false} autoFocus
                    value={pwd} onChange={(e) => setPwd(e.target.value)}
                  />
                </div>
                <div>
                  <label className="text-xs text-mk-mute">Повторите пароль</label>
                  <input
                    className="input" type="password" name="roszetta-device-user-password2"
                    autoComplete="new-password" spellCheck={false}
                    value={pwd2} onChange={(e) => setPwd2(e.target.value)}
                  />
                </div>
              </>
            ) : (
              <>
                <p className="text-xs text-mk-err">
                  Пользователь будет удалён на устройствах: {selected.length}. Это действие нельзя отменить.
                </p>
                <div>
                  <label className="text-xs text-mk-mute">Для подтверждения введите логин: {login}</label>
                  <input
                    className="input" autoComplete="off" spellCheck={false} autoFocus
                    value={confirmText} onChange={(e) => setConfirmText(e.target.value)}
                  />
                </div>
              </>
            )}

            {modalErr && <div className="text-sm text-mk-err">{modalErr}</div>}
            <div className="flex justify-end gap-2">
              <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" onClick={()=>{if(!busy)closeModal()}}>
                Отмена
              </button>
              <button className={mode === 'delete' ? 'btn-primary !text-xs' : 'btn-primary !text-xs'} disabled={busy}>
                {busy ? 'Ставим в очередь…' : mode === 'delete' ? 'Удалить' : mode === 'password' ? 'Сменить' : 'Добавить'}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
