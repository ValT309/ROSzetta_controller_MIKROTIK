import { useEffect, useMemo, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Terminal, Play, AlertTriangle, HardDrive, Users, Shield, KeyRound, Network, ArrowLeftRight, ListChecks, Code } from 'lucide-react';
import { api, CLIRunOut, Device } from '@/api/client';
import FirmwarePage from '@/pages/Firmware';
import AutomationDevicePicker from '@/components/AutomationDevicePicker';
import TimePanel from '@/components/TimePanel';
import DeviceUsersPanel from '@/components/DeviceUsersPanel';
import IpServicesPanel from '@/components/IpServicesPanel';
import TopologyPanel from '@/components/TopologyPanel';
import MultiWanPanel from '@/components/MultiWanPanel';
import AddressListsPanel from '@/components/AddressListsPanel';
import CliConverter from '@/components/CliConverter';
import ConnectionPanel from '@/components/ConnectionPanel';
import CredentialProfilesPanel from '@/components/CredentialProfilesPanel';
import ObjectConstructor from '@/components/ObjectConstructor';

const PRESETS = [
  '/system/identity/print',
  '/system/resource/print',
  '/interface/print',
  '/ip/address/print',
  '/ip/route/print',
  '/system/clock/print',
  '/log/print',
  '/user/group/print',
  '/user/group/add name=roszetta policy=api,read,write,policy,test,ftp,sensitive,reboot',
];

const DANGEROUS = [
  '/system/reboot',
  '/system/shutdown',
  '/system/reset-configuration',
  '/system/routerboard/upgrade',
  '/file/remove',
];

const TAB_KEYS = [
  'cli', 'firmware', 'users', 'services',
  'connection', 'topology', 'multiwan', 'addrlists', 'converter', 'constructor', 'time',
];

export default function CLIPage() {
  const [params] = useSearchParams();
  const [devices, setDevices] = useState<Device[]>([]);
  const initialIds = (params.get('ids') ?? '').split(',').map(Number).filter(Boolean);
  const [selected, setSelected] = useState<Set<number>>(new Set(initialIds));
  const [command, setCommand] = useState('/system/resource/print');
  const [out, setOut] = useState<CLIRunOut | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<'cli' | 'firmware' | 'users' | 'services' | 'connection' | 'topology' | 'multiwan' | 'addrlists' | 'converter' | 'constructor' | 'time'>(() => {
    const h = (typeof window !== 'undefined' ? window.location.hash : '').replace('#', '');
    if (h === 'firmware' || h === 'cli' || h === 'users' || h === 'services' || h === 'connection' || h === 'topology' || h === 'multiwan' || h === 'addrlists' || h === 'converter' || h === 'constructor' || h === 'time') return h;
    return 'cli';
  });

  const location = useLocation();
  const navigate = useNavigate();

  // ссылка вида /…#users (например, из левого меню) переключает вкладку
  useEffect(() => {
    const h = location.hash.replace('#', '');
    if (TAB_KEYS.includes(h) && h !== tab) setTab(h as typeof tab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.key, location.hash]);

  // выбор вкладки на странице обновляет #хеш адреса
  useEffect(() => {
    if (location.hash !== `#${tab}`) {
      navigate({ pathname: location.pathname, search: location.search, hash: `#${tab}` }, { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab]);

  useEffect(() => {
    api.get<Device[]>('/devices').then((r) => setDevices(r.data));
  }, []);

  const isDangerous = useMemo(
    () => DANGEROUS.some((p) => command.trim().startsWith(p)),
    [command],
  );

  const splitStatements = (text: string): string[] => {
    const joined = text.replace(/\\\r?\n[ \t]*/g, ' ');
    return joined.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  };
  const isDangerousStmt = (c: string) =>
    DANGEROUS.some((x) => c.startsWith(x)) || /(^|[\s/])remove(\s|$)/.test(c);

  const run = async () => {
    setErr(null);
    if (selected.size === 0) { setErr('Выберите хотя бы одно устройство'); return; }
    if (!command.trim()) { setErr('Введите команду'); return; }
    const stmts = /[{}]/.test(command) ? [command.trim()] : splitStatements(command);
    if (stmts.length === 0) { setErr('Введите команду'); return; }
    const risky = stmts.filter(isDangerousStmt);
    if (risky.length && !confirm(`Опасные команды!\n\n${risky.join('\n')}\n\nЗапустить на ${selected.size} устройств?`)) {
      return;
    }
    setBusy(true);
    try {
      if (stmts.length === 1) {
        const r = await api.post<CLIRunOut>('/cli/run', {
          device_ids: Array.from(selected),
          command: stmts[0],
          confirm: isDangerousStmt(stmts[0]),
        });
        setOut(r.data);
      } else {
        const results: any[] = [];
        for (const stmt of stmts) {
          try {
            const r = await api.post<CLIRunOut>('/cli/run', {
              device_ids: Array.from(selected),
              command: stmt,
              confirm: isDangerousStmt(stmt),
            });
            for (const x of r.data.results) {
              results.push({ ...x, device_name: `${x.device_name ?? 'device:' + x.device_id}  ←  ${stmt}` });
            }
          } catch (ex: any) {
            const msg = ex?.response?.data?.detail ?? 'Ошибка';
            for (const id of Array.from(selected)) {
              results.push({ device_id: id, device_name: `device:${id}  ←  ${stmt}`, ok: false, error: msg });
            }
          }
        }
        setOut({ command: `${stmts.length} команд`, results } as unknown as CLIRunOut);
      }
    } catch (ex: any) {
      setErr(ex?.response?.data?.detail ?? 'Ошибка');
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Terminal size={16} />
        <h2 className="text-base font-semibold">Автоматизация</h2>
        <span className="text-xs text-mk-mute">CLI и помощник</span>
      </div>

      <div className="flex items-center gap-1 border-b border-mk-border">
        <button
          onClick={() => setTab('cli')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'cli'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <Terminal size={14} /> CLI
        </button>
        <button
          onClick={() => setTab('firmware')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'firmware'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <HardDrive size={14} /> Репозиторий прошивок
        </button>
        <button
          onClick={() => setTab('users')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'users'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <Users size={14} /> Пользователи
        </button>
        <button
          onClick={() => setTab('services')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'services'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <Shield size={14} /> Службы IP
        </button>
        <button onClick={() => setTab('time')} className={`px-3 py-2 text-sm border-b-2 -mb-px ${tab==='time'?'border-mk-accent text-mk-text':'border-transparent text-mk-mute'}`}>Дата и время</button>
        <button
          onClick={() => setTab('topology')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'topology'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <Network size={14} /> Топология
        </button>
        <button
          onClick={() => setTab('multiwan')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'multiwan'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <ArrowLeftRight size={14} /> Multi-WAN
        </button>
        <button
          onClick={() => setTab('addrlists')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'addrlists'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <ListChecks size={14} /> Address-листы
        </button>
        <button
          onClick={() => setTab('converter')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'converter'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <Code size={14} /> Конвертер
        </button>
        <button
          onClick={() => setTab('constructor')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'constructor'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <Network size={14} /> Конструктор объектов
        </button>
        <button
          onClick={() => setTab('connection')}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-sm border-b-2 -mb-px transition-colors ${
            tab === 'connection'
              ? 'border-mk-accent text-mk-text'
              : 'border-transparent text-mk-mute hover:text-mk-text'
          }`}
        >
          <KeyRound size={14} /> Подключение
        </button>
      </div>

      {tab === 'firmware' && <FirmwarePage embedded />}
      {tab === 'users' && <DeviceUsersPanel />}
      {tab === 'services' && <IpServicesPanel />}
      {tab === 'time' && <TimePanel />}
      {tab === 'topology' && <TopologyPanel />}
      {tab === 'multiwan' && <MultiWanPanel />}
      {tab === 'addrlists' && <AddressListsPanel />}
      {tab === 'converter' && <CliConverter onUse={(c) => { setCommand(c); setTab('cli'); }} />}
      {tab === 'constructor' && <ObjectConstructor />}
      {tab === 'connection' && (
        <div className="space-y-3">
          <CredentialProfilesPanel />
          <ConnectionPanel />
        </div>
      )}

      {tab === 'cli' && (
      <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="card p-3">
          <AutomationDevicePicker devices={devices} selected={Array.from(selected)} setSelected={ids=>setSelected(new Set(ids))} disabled={busy} compact/>
        </div>

        <div className="card p-3 md:col-span-2 space-y-2">
          <h3 className="text-xs uppercase tracking-wider text-mk-mute">Команда</h3>
          <textarea
            className="input font-mono text-sm h-20"
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            placeholder="/system/resource/print"
          />
          <div className="flex flex-wrap gap-1">
            {PRESETS.map((p) => (
              <button
                key={p}
                className="text-[11px] px-2 py-0.5 rounded bg-mk-panel2 hover:bg-mk-panel2/60 text-mk-mute font-mono"
                onClick={() => setCommand(p)}
              >{p}</button>
            ))}
          </div>
          {isDangerous && (
            <div className="text-xs text-mk-warn flex items-center gap-1.5">
              <AlertTriangle size={12} /> Опасная команда — потребуется подтверждение
            </div>
          )}
          {err && <div className="text-sm text-mk-err">{err}</div>}
          <div className="flex justify-end">
            <button className="btn-primary" onClick={run} disabled={busy}>
              <Play size={14} /> {busy ? 'Выполнение…' : 'Запустить'}
            </button>
          </div>
        </div>
      </div>

      {out && (
        <div className="card p-0 overflow-hidden">
          <div className="px-3 py-2 border-b border-mk-border text-xs text-mk-mute font-mono">
            $ {out.command}
          </div>
          <div className="divide-y divide-mk-border">
            {out.results.map((r, i) => (
              <div key={`${r.device_id}-${i}`} className="p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`w-2 h-2 rounded-full ${r.ok ? 'bg-mk-ok' : 'bg-mk-err'}`} />
                  <span className="text-sm font-medium">{r.device_name ?? `device:${r.device_id}`}</span>
                </div>
                {r.error && <div className="text-xs text-mk-err font-mono">{r.error}</div>}
                {r.ok && r.rows && (
                  <pre className="text-[11px] font-mono bg-mk-bg p-2 rounded overflow-auto max-h-64">
                    {JSON.stringify(r.rows, null, 2)}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      </div>
      )}
    </div>
  );
}
