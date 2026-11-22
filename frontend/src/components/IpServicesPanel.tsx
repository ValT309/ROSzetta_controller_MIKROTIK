import { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';
import { api, type Device } from '@/api/client';
import ManagementBatch from './ManagementBatch';
import AutomationDevicePicker from './AutomationDevicePicker';

type Mode = 'add' | 'remove' | 'set';

type DevRow = Device;

interface Res {
  device_id: number;
  device_name: string | null;
  ok: boolean;
  action: string | null;
  before: string | null;
  after: string | null;
  note: string | null;
  error: string | null;
}

const SERVICES = ['winbox', 'ssh', 'telnet', 'ftp', 'www', 'www-ssl', 'api', 'api-ssl'];

const MODES: { key: Mode; label: string }[] = [
  { key: 'add', label: 'Добавить к списку' },
  { key: 'remove', label: 'Убрать из списка' },
  { key: 'set', label: 'Заменить список' },
];

const ACTION_LABEL: Record<string, string> = {
  read: 'текущее значение',
  changed: 'изменено',
  unchanged: 'без изменений',
  skipped: 'пропущено',
};

const show = (v: string | null) => (v ? v.split(',').join(', ') : 'любой адрес');

export default function IpServicesPanel() {
  const [devices, setDevices] = useState<DevRow[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [service, setService] = useState('winbox');
  const [mode, setMode] = useState<Mode>('add');
  const protectedService=service==='api'||service==='api-ssl';
  const [addresses, setAddresses] = useState('');
  const [allowAny, setAllowAny] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<Res[] | null>(null);

  useEffect(() => {
    api.get<DevRow[]>('/devices').then((r) => setDevices(r.data)).catch(() => {});
  }, []);


  const errText = (ex: any) => {
    const d = ex?.response?.data?.detail;
    return typeof d === 'string' ? d : 'Запрос не выполнен';
  };

  const readCurrent = async () => {
    setError(null);
    setResults(null);
    if (!selected.length) { setError('Выберите хотя бы одно устройство'); return; }
    setBusy(true);
    try {
      const r = await api.post<{ results: Res[] }>('/cli/ip-service/read', {
        device_ids: selected, service,
      });
      setResults(r.data.results);
    } catch (ex) {
      setError(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    setError(null);
    setResults(null);
    if(protectedService){setError('Используйте очередь добавления IPv4 контроллера ниже');return;}
    if (!selected.length) { setError('Выберите хотя бы одно устройство'); return; }
    if (!(mode === 'set' && allowAny) && !addresses.trim()) {
      setError('Укажите хотя бы один адрес');
      return;
    }
    const what =
      mode === 'set' && allowAny
        ? 'ОЧИСТИТЬ список (служба станет доступна с любого адреса)'
        : `${MODES.find((m) => m.key === mode)?.label.toLowerCase()}: ${addresses.trim()}`;
    if (!window.confirm(
      `Служба ${service}, устройств: ${selected.length}\n\n${what}\n\n` +
      'Если вашего адреса не будет в списке, вы потеряете доступ к службе на этих устройствах. Продолжить?',
    )) return;
    setBusy(true);
    try {
      const r = await api.post<{ results: Res[] }>('/cli/ip-service/set', {
        device_ids: selected, service, mode,
        addresses: addresses.trim(), allow_any: mode === 'set' && allowAny,
      });
      setResults(r.data.results);
    } catch (ex) {
      setError(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <Shield size={14} className="text-mk-accent2" />
        <h3 className="text-sm font-semibold">Разрешённые адреса служб (IP → Services → Available From)</h3>
      </div>
      <p className="text-xs text-mk-mute">
        API и API-SSL доступны для чтения. Добавить IPv4 контроллера можно в постоянной очереди ниже. Удаление и замена их адресов запрещены.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <div>
          <label className="text-xs text-mk-mute">Служба</label>
          <select className="input" value={service} onChange={(e) => { setService(e.target.value); setResults(null); }}>
            {SERVICES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="md:col-span-2">
          <label className="text-xs text-mk-mute">Действие</label>
          <div className="flex gap-1">
            {MODES.map((m) => (
              <button
                key={m.key}
                type="button"
                disabled={protectedService||busy}
                onClick={() => setMode(m.key)}
                className={`text-xs px-3 py-2 rounded border ${
                  mode === m.key ? 'border-mk-accent2 text-mk-accent2' : 'border-white/10 text-mk-mute hover:bg-white/10'
                }`}
              >
                {m.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div>
        <label className="text-xs text-mk-mute">Адреса или подсети через запятую</label>
        <input
          className="input"
          placeholder="195.128.153.202, 10.123.0.0/16"
          value={addresses}
          disabled={protectedService||(mode === 'set' && allowAny)}
          onChange={(e) => setAddresses(e.target.value)}
        />
      </div>
      {!protectedService&&mode === 'set' && (
        <label className="flex items-center gap-2 text-xs text-mk-err cursor-pointer">
          <input type="checkbox" checked={allowAny} onChange={(e) => setAllowAny(e.target.checked)} />
          Очистить список: служба станет доступна с любого адреса (небезопасно)
        </label>
      )}

      <AutomationDevicePicker devices={devices} selected={selected} setSelected={setSelected} disabled={busy}/>

      <div className="flex gap-2">
        <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={busy} onClick={readCurrent}>
          Показать текущие
        </button>
        <button type="button" className="btn-primary !text-xs" disabled={busy||protectedService} onClick={apply}>
          {busy ? 'Выполняем…' : 'Применить'}
        </button>
      </div>

      <ManagementBatch devices={devices.filter(d=>selected.includes(d.id))}/>
      {error && <div className="text-sm text-mk-err">{error}</div>}

      {results && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-mk-mute">
                <th className="py-1 pr-3">Устройство</th>
                <th className="py-1 pr-3">Было</th>
                <th className="py-1 pr-3">Стало</th>
                <th className="py-1">Результат</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => (
                <tr key={r.device_id} className="border-t border-white/5 align-top">
                  <td className="py-1.5 pr-3">{r.device_name || `#${r.device_id}`}</td>
                  {r.ok ? (
                    <>
                      <td className="py-1.5 pr-3 font-mono text-xs">{show(r.before)}</td>
                      <td className="py-1.5 pr-3 font-mono text-xs">{r.action === 'read' ? '—' : show(r.after)}</td>
                      <td className={`py-1.5 ${r.action === 'changed' ? 'text-mk-ok' : 'text-mk-mute'}`}>
                        {ACTION_LABEL[r.action || ''] || 'готово'}
                        {r.note && <div className="text-xs">{r.note}</div>}
                      </td>
                    </>
                  ) : (
                    <td colSpan={3} className="py-1.5 text-mk-err">{r.error}</td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
