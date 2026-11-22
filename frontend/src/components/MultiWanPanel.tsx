import { useEffect, useState } from 'react';
import { ArrowLeftRight } from 'lucide-react';
import { api, Device } from '@/api/client';
import AutomationDevicePicker from './AutomationDevicePicker';

interface Wan {
  name: string;
  kind: 'pppoe' | 'static';
  interface: string;
  gateway: string;
  check_ip: string;
  distance: number;
}

interface RouteRow {
  role: 'check' | 'default' | 'blackhole' | 'table';
  dst: string;
  gateway: string;
  distance: number | null;
  table: string;
  active: boolean;
  disabled: boolean;
}

interface NwRow {
  host: string;
  comment: string;
  status: string;
  since: string;
}

interface BrRow {
  name: string;
  running: boolean;
  disabled: boolean;
  comment: string;
}

interface Res {
  device_id: number;
  device_name: string | null;
  ok: boolean;
  message: string | null;
  errors: string[];
  warnings: string[];
  commands: string[];
  routes: RouteRow[];
  netwatch: NwRow[];
  bridges?: BrRow[];
}

const DEFAULT_WANS: Wan[] = [
  { name: 'PPPoE', kind: 'pppoe', interface: 'pppoe-out1', gateway: '', check_ip: '77.88.8.88', distance: 1 },
  { name: 'MTS', kind: 'static', interface: 'vlan10', gateway: '', check_ip: '77.88.8.1', distance: 2 },
];

const ROLE_LABEL: Record<string, string> = {
  check: 'проверка',
  default: 'default',
  blackhole: 'blackhole',
  table: 'таблица',
};

export default function MultiWanPanel() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [wans, setWans] = useState<Wan[]>(DEFAULT_WANS);
  const [masquerade, setMasquerade] = useState(true);
  const [disableOthers, setDisableOthers] = useState(true);
  const [netwatch, setNetwatch] = useState(true);
  const [interval, setIntervalSec] = useState(30);
  const [nwBridges, setNwBridges] = useState(true);
  const [mangle, setMangle] = useState(false);
  const [exportBefore, setExportBefore] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<Res[] | null>(null);
  const [open, setOpen] = useState<Set<number>>(new Set());

  useEffect(() => {
    api.get<Device[]>('/devices').then((r) => setDevices(r.data)).catch(() => {});
  }, []);


  const setWan = (i: number, patch: Partial<Wan>) =>
    setWans((w) => w.map((x, k) => (k === i ? { ...x, ...patch } : x)));

  const call = async (action: 'preview' | 'apply' | 'status' | 'remove') => {
    setError(null);
    setResults(null);
    if (!selected.length) { setError('Выберите хотя бы одно устройство'); return; }
    if (action === 'apply' && !window.confirm(
      `Применить Multi-WAN на устройствах: ${selected.length}?\n\n` +
      'Роутер сам откатит изменения через 5 минут, если после применения контроллер не сможет к нему подключиться. ' +
      'Сначала сделайте предпросмотр и бэкап.',
    )) return;
    if (action === 'remove' && !window.confirm(
      `Удалить настройку Multi-WAN на устройствах: ${selected.length} и вернуть прежние маршруты?`,
    )) return;
    setBusy(true);
    try {
      const body: Record<string, unknown> =
        action === 'status' || action === 'remove'
          ? { device_ids: selected }
          : {
              device_ids: selected,
              wans: wans.map((w) => ({ ...w, distance: Number(w.distance) })),
              masquerade,
              disable_other_defaults: disableOthers,
              netwatch,
              netwatch_interval: Number(interval),
              netwatch_bridges: nwBridges,
              mangle,
              export_before: exportBefore,
            };
      const r = await api.post<{ results: Res[] }>(`/mwan/${action}`, body);
      setResults(r.data.results);
      setOpen(new Set(
        r.data.results
          .filter((x) => !x.ok || x.errors.length || x.warnings.length || x.commands.length || x.routes.length || x.netwatch.length)
          .map((x) => x.device_id),
      ));
    } catch (ex: any) {
      const d = ex?.response?.data?.detail;
      setError(typeof d === 'string' ? d : 'Запрос не выполнен');
    } finally {
      setBusy(false);
    }
  };

  const toggleOpen = (id: number) =>
    setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <ArrowLeftRight size={14} className="text-mk-accent2" />
        <h3 className="text-sm font-semibold">Multi-WAN: резервирование через рекурсивную маршрутизацию</h3>
      </div>
      <p className="text-xs text-mk-mute">
        Проверочный адрес каждого провайдера пингуется только через этого провайдера. Меньший distance это основной канал.
        Если проверка не проходит, трафик уходит на следующий. Перед изменениями на роутере запускается откат на 5 минут,
        который отменяется только после успешной повторной проверки связи.
      </p>

      <div className="space-y-2">
        {wans.map((w, i) => (
          <div key={i} className="grid grid-cols-2 md:grid-cols-6 gap-2 items-end">
            <div>
              <label className="text-xs text-mk-mute">Название</label>
              <input className="input" value={w.name} onChange={(e) => setWan(i, { name: e.target.value })} />
            </div>
            <div>
              <label className="text-xs text-mk-mute">Тип</label>
              <select className="input" value={w.kind} onChange={(e) => setWan(i, { kind: e.target.value as Wan['kind'] })}>
                <option value="pppoe">PPPoE</option>
                <option value="static">Статика</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-mk-mute">{w.kind === 'pppoe' ? 'PPPoE-клиент' : 'Интерфейс'}</label>
              <input className="input" value={w.interface} onChange={(e) => setWan(i, { interface: e.target.value })} />
            </div>
            <div>
              <label className="text-xs text-mk-mute">Шлюз (для статики)</label>
              <input
                className="input" value={w.gateway} disabled={w.kind !== 'static'}
                placeholder={w.kind === 'static' ? '203.0.113.1' : 'не нужен'}
                onChange={(e) => setWan(i, { gateway: e.target.value })}
              />
            </div>
            <div>
              <label className="text-xs text-mk-mute">Проверочный адрес</label>
              <input className="input" value={w.check_ip} onChange={(e) => setWan(i, { check_ip: e.target.value })} />
            </div>
            <div>
              <label className="text-xs text-mk-mute">Distance</label>
              <input
                className="input" type="number" min={1} max={254} value={w.distance}
                onChange={(e) => setWan(i, { distance: Number(e.target.value) })}
              />
            </div>
          </div>
        ))}
        <div className="flex gap-3 text-xs">
          {wans.length < 3 && (
            <button type="button" className="text-mk-accent2"
              onClick={() => setWans((w) => [...w, { name: 'ISP3', kind: 'static', interface: '', gateway: '', check_ip: '9.9.9.9', distance: 3 }])}>
              + третий провайдер
            </button>
          )}
          {wans.length > 2 && (
            <button type="button" className="text-mk-mute" onClick={() => setWans((w) => w.slice(0, -1))}>убрать последнего</button>
          )}
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer">
          <input type="checkbox" checked={masquerade} onChange={(e) => setMasquerade(e.target.checked)} />
          Создать masquerade (NAT) на выходных интерфейсах провайдеров
        </label>
        <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer">
          <input type="checkbox" checked={disableOthers} onChange={(e) => setDisableOthers(e.target.checked)} />
          Отключить прежние статические default-маршруты таблицы main (не удаляются, откат их включит)
        </label>
        <label className="flex flex-wrap items-center gap-2 text-xs text-mk-mute cursor-pointer">
          <input type="checkbox" checked={netwatch} onChange={(e) => setNetwatch(e.target.checked)} />
          Netwatch: проверки по каждому провайдеру (лог UP/DOWN) и blackhole-маршруты до проверочных адресов
          <span className="inline-flex items-center gap-1">
            каждые
            <select className="input !py-0.5 !text-xs !w-auto" value={interval} disabled={!netwatch}
              onChange={(e) => setIntervalSec(Number(e.target.value))}>
              {[10, 30, 60, 120].map((s) => <option key={s} value={s}>{s} с</option>)}
            </select>
          </span>
        </label>
        <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer pl-5">
          <input type="checkbox" checked={nwBridges} disabled={!netwatch} onChange={(e) => setNwBridges(e.target.checked)} />
          Мониторные bridge (mon-wan1, mon-wan2…): пустые, без ARP; скрипты netwatch включают и выключают их вместе с каналом
        </label>
        <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer">
          <input type="checkbox" checked={mangle} onChange={(e) => setMangle(e.target.checked)} />
          Mangle: ответы на входящие соединения уходят тому провайдеру, откуда они пришли (таблицы rzmw_wanN)
        </label>
        <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer">
          <input type="checkbox" checked={exportBefore} onChange={(e) => setExportBefore(e.target.checked)} />
          Перед применением сохранить на роутере экспорты маршрутов, netwatch, mangle и NAT (файлы rzmw-…-before-….rsc)
        </label>
      </div>

      <AutomationDevicePicker devices={devices} selected={selected} setSelected={setSelected} disabled={busy}/>

      <div className="flex flex-wrap gap-2">
        <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={busy} onClick={() => call('preview')}>
          Предпросмотр
        </button>
        <button type="button" className="btn-primary !text-xs" disabled={busy} onClick={() => call('apply')}>
          {busy ? 'Выполняем…' : 'Применить'}
        </button>
        <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={busy} onClick={() => call('status')}>
          Статус
        </button>
        <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10 text-mk-err" disabled={busy} onClick={() => call('remove')}>
          Удалить настройку
        </button>
      </div>

      {error && <div className="text-sm text-mk-err">{error}</div>}

      {results && (
        <div className="divide-y divide-white/5">
          {results.map((r) => {
            const isOpen = open.has(r.device_id);
            const details = r.errors.length || r.warnings.length || r.commands.length || r.routes.length || r.netwatch.length || (r.bridges ?? []).length;
            return (
              <div key={r.device_id} className="py-2">
                <div className="flex items-center gap-2 text-sm cursor-pointer" onClick={() => details && toggleOpen(r.device_id)}>
                  <span className={r.ok ? 'text-mk-ok' : 'text-mk-err'}>●</span>
                  <span className="font-medium">{r.device_name || `#${r.device_id}`}</span>
                  <span className={r.ok ? 'text-mk-mute' : 'text-mk-err'}>{r.message}</span>
                  {details ? <span className="ml-auto text-xs text-mk-mute">{isOpen ? 'скрыть' : 'подробнее'}</span> : null}
                </div>
                {isOpen && (
                  <div className="mt-2 space-y-2">
                    {r.errors.map((e, i) => <div key={`e${i}`} className="text-xs text-mk-err">· {e}</div>)}
                    {r.warnings.map((e, i) => <div key={`w${i}`} className="text-xs text-mk-warn">· {e}</div>)}
                    {r.commands.length > 0 && (
                      <pre className="text-[11px] font-mono bg-mk-bg p-2 rounded overflow-auto max-h-64">{r.commands.join('\n')}</pre>
                    )}
                    {r.routes.length > 0 && (
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-left text-mk-mute">
                            <th className="py-1 pr-3">Тип</th><th className="py-1 pr-3">Назначение</th>
                            <th className="py-1 pr-3">Шлюз</th><th className="py-1 pr-3">Distance</th>
                            <th className="py-1 pr-3">Таблица</th><th className="py-1">Состояние</th>
                          </tr>
                        </thead>
                        <tbody>
                          {r.routes.map((x, i) => (
                            <tr key={i} className="border-t border-white/5">
                              <td className="py-1 pr-3">{ROLE_LABEL[x.role] || x.role}</td>
                              <td className="py-1 pr-3 font-mono">{x.dst}</td>
                              <td className="py-1 pr-3 font-mono">{x.gateway}</td>
                              <td className="py-1 pr-3">{x.distance ?? '—'}</td>
                              <td className="py-1 pr-3 font-mono">{x.table}</td>
                              <td className={`py-1 ${x.disabled ? 'text-mk-mute' : x.active ? 'text-mk-ok' : 'text-mk-warn'}`}>
                                {x.disabled ? 'отключён' : x.active ? 'активен' : 'неактивен'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                    {(r.bridges ?? []).length > 0 && (
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-left text-mk-mute">
                            <th className="py-1 pr-3">Bridge</th><th className="py-1 pr-3">Описание</th><th className="py-1">Состояние</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(r.bridges ?? []).map((x, i) => (
                            <tr key={i} className="border-t border-white/5">
                              <td className="py-1 pr-3 font-mono">{x.name}</td>
                              <td className="py-1 pr-3">{x.comment || '—'}</td>
                              <td className={`py-1 ${x.disabled ? 'text-mk-err' : 'text-mk-ok'}`}>
                                {x.disabled ? 'выключен (канал недоступен)' : x.running ? 'включён (канал доступен)' : 'включён'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                    {r.netwatch.length > 0 && (
                      <table className="w-full text-xs">
                        <thead>
                          <tr className="text-left text-mk-mute">
                            <th className="py-1 pr-3">Netwatch</th><th className="py-1 pr-3">Хост</th>
                            <th className="py-1 pr-3">Статус</th><th className="py-1">С</th>
                          </tr>
                        </thead>
                        <tbody>
                          {r.netwatch.map((x, i) => (
                            <tr key={i} className="border-t border-white/5">
                              <td className="py-1 pr-3">{x.comment || '—'}</td>
                              <td className="py-1 pr-3 font-mono">{x.host}</td>
                              <td className={`py-1 pr-3 ${x.status === 'up' ? 'text-mk-ok' : x.status === 'down' ? 'text-mk-err' : 'text-mk-mute'}`}>
                                {x.status}
                              </td>
                              <td className="py-1 font-mono text-mk-mute">{x.since || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
