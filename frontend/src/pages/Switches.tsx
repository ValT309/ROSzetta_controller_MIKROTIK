import {EditInventory,InventorySummary} from "@/components/DeviceInventory";
import DevicePreview from '@/components/DevicePreview';
import { InternetOn, InternetOff } from '@/components/InternetIcon';
import {portForTLS, normalizePin, connectionError} from '@/utils/deviceConnection';
import {SSLMark} from '@/components/SSLStatus';
import {EditIdentity,BulkCategory} from '@/components/DeviceManagement';
import { useDeviceTable, DeviceToolbar, SortHeader, BackupCell } from '@/components/DeviceManagerTable';
import DeviceBatch from '@/components/DeviceBatch';
import { FormEvent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Plus, Trash2, Pencil } from 'lucide-react';
import { api, Device } from '@/api/client';
import WinboxButton from '@/components/WinboxButton';
import { GroupHeaderRow, GroupSelect, buildGroupRows, useCollapsedGroups } from '@/components/DeviceGroups';
import CredentialSelect from '@/components/CredentialSelect';

function StatusDot({ status }: { status: string }) {
  const cls =
    status === 'up'   ? 'bg-mk-ok'   :
    status === 'down' ? 'bg-mk-err'  :
                        'bg-mk-mute' ;
  return <span className={`inline-block w-2 h-2 rounded-full ${cls} flex-shrink-0`} />;
}

export default function SwitchesPage() {
  const [list, setList] = useState<Device[]>([]);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<Device | null>(null);
  const { collapsed, toggle: toggleGroup } = useCollapsedGroups('switches');
  const table = useDeviceTable(list);
  const rows = table.grouped ? buildGroupRows(table.filtered, collapsed) : table.filtered.map((device, i) => ({kind: 'device' as const, device, index: i+1}));
  const visible = rows.flatMap(row => row.kind === 'device' ? [row.device.id] : []);
  const [batch, setBatch] = useState<Device[] | null>(null);

  const reload = () =>
    api.get<Device[]>('/devices', { params: { kind: 'switch' } }).then((r) => setList(r.data));

  useEffect(() => { reload(); }, []);

  const remove = async (id: number) => {
    if (!confirm('Удалить свич?')) return;
    await api.delete(`/devices/${id}`);
    await reload();
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-end items-center">
        <button className="btn-primary !py-1 !text-xs" onClick={() => setOpen(true)}>
          <Plus size={13} /> Добавить
        </button>
      </div>

      <DeviceToolbar table={table} visible={visible} onBatch={() => setBatch(list.filter(d => table.selected.includes(d.id)))} onReload={reload}/>
      <BulkCategory devices={list.filter(d=>table.selected.includes(d.id))} onSaved={()=>{void reload();}}/>
      <div className="card p-0 overflow-x-auto">
        <table className="w-full text-[13px]">
          <thead className="bg-mk-panel2 text-mk-mute text-[10px] uppercase tracking-wider">
            <tr>
              <th className="px-2 py-1"><input type="checkbox" aria-label="Выбрать видимые устройства" checked={visible.length>0 && visible.every(id=>table.selected.includes(id))} onChange={e=>table.selectVisible(visible,e.target.checked)}/></th>
              <th className="text-left px-2 py-1 w-8">#</th>
              <th className="text-left px-2 py-1 w-5"></th>
              <SortHeader table={table} field="name" label="Имя"/>
              <SortHeader table={table} field="host" label="Хост"/><SortHeader table={table} field="ssl" label="SSL"/>
              <SortHeader table={table} field="model" label="Модель"/>
              <SortHeader table={table} field="version" label="RouterOS"/>
              <SortHeader table={table} field="internet" label="Internet"/>
              <SortHeader table={table} field="status" label="Статус"/>
              <SortHeader table={table} field="backup" label="Последний бэкап"/>
              <th className="text-right px-2 py-1 w-28"></th>
            </tr>
          </thead>
          <tbody>
            {table.filtered.length === 0 && (
              <tr><td colSpan={12} className="px-3 py-3 text-center text-mk-mute">Нет свичей</td></tr>
            )}
            {rows.map((row) => {
              if (row.kind === 'group') {
                return (
                  <GroupHeaderRow
                    key={`g:${row.name}`}
                    colSpan={12}
                    name={row.name}
                    count={row.count}
                    down={row.down}
                    collapsed={row.collapsed}
                    onToggle={() => toggleGroup(row.name)}
                  />
                );
              }
              const d = row.device;
              const idx = row.index - 1;
              return (
              <tr key={d.id} className="border-t border-mk-border hover:bg-mk-panel2/40">
                <td className="px-2 py-0.5"><input type="checkbox" aria-label={`Выбрать ${d.identity || d.name}`} checked={table.selected.includes(d.id)} onChange={()=>table.toggle(d.id)}/></td>
                <td className="px-2 py-0.5 text-mk-mute text-xs">{idx + 1}</td>
                <td className="px-2 py-0.5"><StatusDot status={d.status} /></td>
                <td className="px-2 py-0.5">
                  <Link to={`/devices/${d.id}`} className="text-mk-accent2 hover:underline">
                    {d.identity || d.name}
                  </Link><EditIdentity device={d} onSaved={reload}/><EditInventory device={d} onSaved={reload}/>{table.showInventory&&<InventorySummary device={d}/>}
                  {d.last_error && (
                    <div className="text-[10px] text-mk-err truncate max-w-[260px]" title={d.last_error}>
                      {d.last_error}
                    </div>
                  )}
                </td>
                <td className="px-2 py-0.5 text-mk-mute">{d.host}:{d.port}{d.use_tls ? ' (TLS)' : ''}</td><td className="px-2 py-0.5"><SSLMark info={table.sslInfo[String(d.id)]} device={d}/></td>
                <td className="px-2 py-0.5"><DevicePreview model={d.model} kind={d.kind}/></td>
                <td className="px-2 py-0.5">{d.ros_version || '—'}</td>
                <td className="px-2 py-0.5">
                  {d.internet_ok === true && <span title="Интернет доступен"><InternetOn size={15} className="text-mk-ok" /></span>}
                  {d.internet_ok === false && <span title="Нет интернета"><InternetOff size={15} className="text-mk-warn" /></span>}
                  {d.internet_ok === null && <span className="text-mk-mute">—</span>}
                </td>
                <td className="px-2 py-0.5">
                  <span className={`text-[10px] px-1.5 py-0.5 ${
                    d.status === 'up' ? 'badge-up' : d.status === 'down' ? 'badge-down' : 'badge-unk'
                  }`}>
                    {d.status.toUpperCase()}
                  </span>
                </td>
                <BackupCell info={table.backupInfo[String(d.id)]}/>
                <td className="px-2 py-0.5 text-right">
                  <WinboxButton host={d.host} className="mr-1" />
                  <button className="btn-ghost !py-0.5 !px-1.5" onClick={() => setEditing(d)} title="Редактировать">
                    <Pencil size={12} />
                  </button>
                  <button className="btn-ghost !py-0.5 !px-1.5 ml-1" onClick={() => remove(d.id)} title="Удалить">
                    <Trash2 size={12} />
                  </button>
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {batch && <DeviceBatch devices={batch} onClose={()=>{setBatch(null); void reload();}}/>}
      {open && <SwitchModal onClose={() => setOpen(false)} onSaved={reload} />}
      {editing && (
        <SwitchModal
          device={editing}
          onClose={() => setEditing(null)}
          onSaved={() => { setEditing(null); reload(); }}
        />
      )}
    </div>
  );
}

function SwitchModal({
  device, onClose, onSaved,
}: {
  device?: Device;
  onClose: () => void;
  onSaved: () => void;
}) {
  const isEdit = !!device;
  const [credentialId, setCredentialId] = useState<number | null>(null);
  const [form, setForm] = useState({
    name: device?.name ?? '',
    host: device?.host ?? '',
    port: device?.port ?? 8728,
    use_tls: device?.use_tls ?? false,
    username: device?.username ?? 'admin',
    password: '',
    group_name: device?.group_name ?? '',
  });
  const [pin, setPin] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true); setErr(null);
    try {
      if (isEdit) {
        const payload: Record<string, unknown> = { ...form };
      if (form.use_tls && pin.trim()) payload.tls_fingerprint = normalizePin(pin);
        if (!payload.password) delete payload.password;
        await api.patch(`/devices/${device!.id}`, payload);
      } else {
        const payload: Record<string, unknown> = { ...form, kind: 'switch' };
        if (form.use_tls && pin.trim()) payload.tls_fingerprint = normalizePin(pin);
        if (credentialId) {
          delete payload.username;
          delete payload.password;
          payload.credential_id = credentialId;
        }
        await api.post('/devices', payload);
      }
      onSaved(); onClose();
    } catch (ex: any) {
      setErr(connectionError(ex));
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md">
        <h3 className="text-base font-semibold mb-4">
          {isEdit ? 'Редактировать свич' : 'Новый свич'}
        </h3>
        <form onSubmit={submit} className="space-y-3">
          {!isEdit && <CredentialSelect value={credentialId} onChange={setCredentialId} />}
          {(['name', 'host', 'username'] as const)
            .filter((k) => !credentialId || k !== 'username')
            .map((k) => (
            <div key={k}>
              <label className="text-xs text-mk-mute">{{name:"Имя",host:"Хост",username:"Логин",password:"Пароль"}[k]}</label>
              <input
                className="input"
                type="text"
                value={(form as any)[k]} disabled={k==='host' && Boolean(device?.tls_fingerprint)}
                onChange={(e) => setForm({ ...form, [k]: e.target.value })}
                required={k !== 'name' || isEdit}
                placeholder={k === 'name' && !isEdit ? 'пусто = взять из system identity' : undefined}
              />
            </div>
          ))}
          <div>
            <label className="text-xs text-mk-mute">Группа (папка)</label>
            <GroupSelect value={form.group_name} onChange={(v) => setForm({ ...form, group_name: v })} />
          </div>
          <div className={credentialId ? 'hidden' : ''}>
            <label className="text-xs text-mk-mute">
              Пароль{isEdit ? ' (оставьте пустым — без изменений)' : ''}
            </label>
            <input
              className="input"
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              required={!isEdit && !credentialId}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-mk-mute">Порт</label>
              <input
                className="input" type="number" min={1} max={65535} required
                value={form.port} disabled={Boolean(device?.tls_fingerprint)}
                onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
              />
            </div>
            <label className="flex items-end gap-2 text-sm pb-2">
              <input
                type="checkbox" checked={form.use_tls} disabled={Boolean(device?.tls_fingerprint)}
                onChange={(e) => setForm({ ...form, use_tls: e.target.checked, port: portForTLS(form.port, e.target.checked) })}
              />
              api-ssl
            </label>
          </div>
          {device?.tls_fingerprint && <p className="text-xs text-mk-mute">TLS закреплён. Хост, порт и транспорт защищены от случайного изменения.</p>}
          {form.use_tls && !device?.tls_fingerprint && <label className="block text-xs text-mk-mute">SHA-256 сертификата (сверьте с сертификатом MikroTik, 64 hex)<input className="input font-mono" required={!device?.use_tls} value={pin} onChange={e=>setPin(e.target.value)} placeholder="SHA-256" /></label>}
          <p className="text-xs text-mk-mute">Стандартные порты: API 8728, API-SSL 8729. Нестандартный порт задаётся вручную.</p>
          {err && <div className="text-sm text-mk-err">{err}</div>}
          <div className="flex gap-2 justify-end pt-2">
            <button type="button" className="btn-ghost" onClick={onClose}>Отмена</button>
            <button className="btn-primary" disabled={saving}>
              {saving ? 'Сохранение…' : isEdit ? 'Сохранить' : 'Создать'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
