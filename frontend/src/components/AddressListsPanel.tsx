import { useEffect, useMemo, useState } from 'react';
import { ListChecks } from 'lucide-react';
import { api, Device } from '@/api/client';
import AutomationDevicePicker from './AutomationDevicePicker';

type Mode = 'view' | 'add' | 'update' | 'remove' | 'replace';

interface Entry {
  list: string;
  address: string;
  comment: string | null;
  timeout: string | null;
  dynamic: boolean;
  disabled: boolean;
}
interface ListSum { name: string; total: number; dynamic: number }
interface Res {
  device_id: number;
  device_name: string | null;
  ok: boolean;
  message: string | null;
  lists: ListSum[];
  entries: Entry[];
  truncated: boolean;
  lines: string[];
  undo: string[];
  warnings: string[];
  errors: string[];
}

const MODES: { key: Mode; label: string }[] = [
  { key: 'view', label: 'Просмотр и выгрузка' },
  { key: 'add', label: 'Добавить' },
  { key: 'update', label: 'Изменить' },
  { key: 'remove', label: 'Удалить' },
  { key: 'replace', label: 'Заменить содержимое' },
];

const SHOW_ROWS = 300;

const rq = (v: string) =>
  '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$').replace(/\?/g, '\\?') + '"';

const csvCell = (v: unknown) => {
  let s = String(v ?? '');
  if (/^[=+\-@]/.test(s)) s = "'" + s; // защита от формул при открытии в Excel
  return '"' + s.replace(/"/g, '""') + '"';
};

function download(name: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const stamp = () => new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');

export default function AddressListsPanel() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selected, setSelected] = useState<number[]>([]);
  const [mode, setMode] = useState<Mode>('view');
  const [listName, setListName] = useState('');
  const [addresses, setAddresses] = useState('');
  const [wholeList, setWholeList] = useState(false);
  const [comment, setComment] = useState('');
  const [setCommentFlag, setSetCommentFlag] = useState(false);
  const [timeout, setTimeoutVal] = useState('');
  const [state, setState] = useState('keep');
  const [newAddress, setNewAddress] = useState('');
  const [filter, setFilter] = useState('');

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<Res[] | null>(null);
  const [kind, setKind] = useState<'summary' | 'entries' | 'plan' | 'done' | null>(null);
  const [open, setOpen] = useState<Set<number>>(new Set());

  useEffect(() => {
    api.get<Device[]>('/devices').then((r) => setDevices(r.data)).catch(() => {});
  }, []);


  const errText = (ex: any) => {
    const d = ex?.response?.data?.detail;
    return typeof d === 'string' ? d : 'Запрос не выполнен';
  };

  const changeMode = (m: Mode) => {
    setMode(m);
    setResults(null);
    setKind(null);
    setError(null);
  };

  const post = async (url: string, body: Record<string, unknown>, k: typeof kind) => {
    setError(null);
    setResults(null);
    setKind(null);
    setBusy(true);
    try {
      const r = await api.post<{ results: Res[] }>(url, body);
      setResults(r.data.results);
      setKind(k);
      setOpen(new Set(r.data.results.map((x) => x.device_id)));
    } catch (ex) {
      setError(errText(ex));
    } finally {
      setBusy(false);
    }
  };

  const needDevices = () => {
    if (!selected.length) { setError('Выберите хотя бы одно устройство'); return false; }
    return true;
  };

  const viewSummary = () => {
    if (!needDevices()) return;
    post('/address-lists/read', { device_ids: selected, list_name: '', entries: false }, 'summary');
  };

  const viewEntries = () => {
    if (!needDevices()) return;
    post('/address-lists/read', { device_ids: selected, list_name: listName.trim(), entries: true }, 'entries');
  };

  const changeBody = () => ({
    device_ids: selected,
    action: mode,
    list_name: listName.trim(),
    addresses,
    whole_list: wholeList,
    comment: mode === 'update' ? (setCommentFlag ? comment : null) : (comment.trim() ? comment : null),
    timeout: mode === 'add' ? timeout.trim() : '',
    state: mode === 'update' ? state : 'keep',
    new_address: mode === 'update' ? newAddress.trim() : '',
  });

  const changeCheck = () => {
    if (!needDevices()) return false;
    if (!listName.trim()) { setError('Укажите название списка'); return false; }
    return true;
  };

  const preview = () => {
    if (!changeCheck()) return;
    post('/address-lists/preview', changeBody(), 'plan');
  };

  const apply = () => {
    if (!changeCheck()) return;
    const what =
      mode === 'add' ? 'добавить адреса'
      : mode === 'remove' ? (wholeList ? 'удалить ВСЕ статические записи списка' : 'удалить указанные адреса')
      : mode === 'replace' ? 'заменить содержимое списка (лишние записи будут удалены)'
      : 'изменить записи';
    if (!window.confirm(
      `Список «${listName.trim()}», устройств: ${selected.length}\n\nДействие: ${what}.\n\n` +
      'Рекомендуется сначала сделать «Предпросмотр». После применения для удалённых записей можно скачать файл отката.',
    )) return;
    post('/address-lists/apply', changeBody(), 'done');
  };

  const entriesOf = (r: Res) => {
    const q = filter.trim().toLowerCase();
    if (!q) return r.entries;
    return r.entries.filter((e) =>
      `${e.list} ${e.address} ${e.comment ?? ''}`.toLowerCase().includes(q));
  };

  const exportCsv = () => {
    if (!results) return;
    const head = ['device', 'list', 'address', 'comment', 'timeout', 'dynamic', 'disabled'];
    const rows: string[] = [head.join(',')];
    for (const r of results) {
      for (const e of entriesOf(r)) {
        rows.push([r.device_name ?? r.device_id, e.list, e.address, e.comment, e.timeout,
          e.dynamic ? 'yes' : 'no', e.disabled ? 'yes' : 'no'].map(csvCell).join(','));
      }
    }
    download(`address-lists-${stamp()}.csv`, '\ufeff' + rows.join('\r\n'), 'text/csv;charset=utf-8');
  };

  const exportRsc = () => {
    if (!results) return;
    const out: string[] = ['# Выгрузка address-list из ROSzetta (только статические записи)'];
    for (const r of results) {
      out.push('', `# устройство: ${r.device_name ?? r.device_id}`);
      for (const e of entriesOf(r)) {
        if (e.dynamic) continue;
        let line = `/ip firewall address-list add list=${rq(e.list)} address=${rq(e.address)}`;
        if (e.comment) line += ` comment=${rq(e.comment)}`;
        if (e.disabled) line += ' disabled=yes';
        out.push(line);
      }
    }
    download(`address-lists-${stamp()}.rsc`, out.join('\n') + '\n', 'text/plain;charset=utf-8');
  };

  const exportUndo = (r: Res) => {
    const head = [
      `# Откат изменений address-list «${listName.trim()}» на ${r.device_name ?? r.device_id}`,
      '# Динамические записи восстанавливаются как статические, таймаут не сохраняется',
    ];
    download(`undo-${(r.device_name ?? r.device_id).toString().replace(/[^\w.-]+/g, '_')}-${stamp()}.rsc`,
      [...head, ...r.undo].join('\n') + '\n', 'text/plain;charset=utf-8');
  };

  const hasEntries = kind === 'entries' && (results ?? []).some((r) => r.entries.length > 0);
  const toggleOpen = (id: number) =>
    setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  const needAddr = !(wholeList && (mode === 'remove' || mode === 'update'));
  const knownLists = useMemo(() => {
    const set = new Set<string>();
    (results ?? []).forEach((r) => r.lists.forEach((l) => set.add(l.name)));
    return Array.from(set).sort((a, b) => a.localeCompare(b, 'ru'));
  }, [results]);

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <ListChecks size={14} className="text-mk-accent2" />
        <h3 className="text-sm font-semibold">Address-листы (IP → Firewall → Address Lists)</h3>
      </div>

      <div className="flex flex-wrap gap-1">
        {MODES.map((m) => (
          <button
            key={m.key} type="button" onClick={() => changeMode(m.key)}
            className={`text-xs px-3 py-1.5 rounded border ${
              mode === m.key ? 'border-mk-accent2 text-mk-accent2' : 'border-white/10 text-mk-mute hover:bg-white/10'
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>

      <AutomationDevicePicker devices={devices} selected={selected} setSelected={setSelected} disabled={busy}/>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <div>
          <label className="text-xs text-mk-mute">
            Название списка{mode === 'view' ? ' (пусто = все списки)' : ''}
          </label>
          <input
            className="input" value={listName} maxLength={64}
            placeholder={mode === 'view' ? 'например, to_yandex' : ''}
            onChange={(e) => setListName(e.target.value)}
          />
        </div>

        {(mode === 'add' || mode === 'replace') && (
          <div>
            <label className="text-xs text-mk-mute">Комментарий (необязательно)</label>
            <input className="input" value={comment} maxLength={255} onChange={(e) => setComment(e.target.value)} />
          </div>
        )}
        {mode === 'add' && (
          <div>
            <label className="text-xs text-mk-mute">Timeout (необязательно)</label>
            <input className="input" value={timeout} placeholder="1d, 12h, 00:30:00" onChange={(e) => setTimeoutVal(e.target.value)} />
          </div>
        )}
        {mode === 'update' && (
          <>
            <div>
              <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer">
                <input type="checkbox" checked={setCommentFlag} onChange={(e) => setSetCommentFlag(e.target.checked)} />
                Изменить комментарий (пусто = очистить)
              </label>
              <input className="input" value={comment} disabled={!setCommentFlag} maxLength={255} onChange={(e) => setComment(e.target.value)} />
            </div>
            <div>
              <label className="text-xs text-mk-mute">Состояние записей</label>
              <select className="input" value={state} onChange={(e) => setState(e.target.value)}>
                <option value="keep">не менять</option>
                <option value="disable">отключить</option>
                <option value="enable">включить</option>
              </select>
            </div>
          </>
        )}
      </div>

      {mode !== 'view' && (
        <>
          {(mode === 'remove' || mode === 'update') && (
            <label className="flex items-center gap-2 text-xs text-mk-mute cursor-pointer">
              <input type="checkbox" checked={wholeList} onChange={(e) => setWholeList(e.target.checked)} />
              Все статические записи списка (адреса не нужны)
            </label>
          )}
          {needAddr && (
            <div>
              <label className="text-xs text-mk-mute">
                Адреса: IP, подсети (10.0.0.0/24), диапазоны (10.0.0.1-10.0.0.9) или DNS-имена; по одному в строке или через запятую
              </label>
              <textarea
                className="input font-mono text-xs h-28" value={addresses}
                placeholder={'203.0.113.5\n198.51.100.0/24'}
                onChange={(e) => setAddresses(e.target.value)}
              />
            </div>
          )}
          {mode === 'update' && (
            <div className="md:w-1/3">
              <label className="text-xs text-mk-mute">Заменить адрес на (только если выше указан один адрес)</label>
              <input className="input" value={newAddress} onChange={(e) => setNewAddress(e.target.value)} />
            </div>
          )}
        </>
      )}

      <div className="flex flex-wrap gap-2">
        {mode === 'view' ? (
          <>
            <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={busy} onClick={viewSummary}>
              Сводка по спискам
            </button>
            <button type="button" className="btn-primary !text-xs" disabled={busy} onClick={viewEntries}>
              {busy ? 'Загрузка…' : 'Показать записи'}
            </button>
            <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={!hasEntries} onClick={exportCsv}>
              Скачать CSV
            </button>
            <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={!hasEntries} onClick={exportRsc}>
              Скачать .rsc
            </button>
          </>
        ) : (
          <>
            <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" disabled={busy} onClick={preview}>
              Предпросмотр
            </button>
            <button type="button" className="btn-primary !text-xs" disabled={busy} onClick={apply}>
              {busy ? 'Выполняем…' : 'Применить'}
            </button>
          </>
        )}
      </div>

      {error && <div className="text-sm text-mk-err">{error}</div>}

      {kind === 'entries' && results && (
        <div>
          <label className="text-xs text-mk-mute">Фильтр по результатам (адрес или комментарий)</label>
          <input className="input md:w-1/3" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </div>
      )}

      {results && (
        <div className="divide-y divide-white/5">
          {results.map((r) => {
            const isOpen = open.has(r.device_id);
            const ents = entriesOf(r);
            const details = r.lists.length || r.entries.length || r.lines.length || r.warnings.length || r.errors.length;
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

                    {kind === 'summary' && r.lists.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {r.lists.map((l) => (
                          <button
                            key={l.name} type="button" title="Подставить название списка"
                            className="text-xs px-2 py-0.5 rounded border border-white/10 hover:bg-white/10"
                            onClick={() => setListName(l.name)}
                          >
                            {l.name} ({l.total}{l.dynamic ? `, дин. ${l.dynamic}` : ''})
                          </button>
                        ))}
                      </div>
                    )}

                    {kind === 'entries' && (
                      <>
                        {r.truncated && (
                          <div className="text-xs text-mk-warn">Показаны первые записи, укажите название списка, чтобы сузить выборку.</div>
                        )}
                        {ents.length > 0 && (
                          <div className="overflow-auto max-h-80">
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="text-left text-mk-mute">
                                  <th className="py-1 pr-3">Список</th><th className="py-1 pr-3">Адрес</th>
                                  <th className="py-1 pr-3">Комментарий</th><th className="py-1 pr-3">Timeout</th><th className="py-1">Флаги</th>
                                </tr>
                              </thead>
                              <tbody>
                                {ents.slice(0, SHOW_ROWS).map((e, i) => (
                                  <tr key={i} className="border-t border-white/5">
                                    <td className="py-1 pr-3">{e.list}</td>
                                    <td className="py-1 pr-3 font-mono">{e.address}</td>
                                    <td className="py-1 pr-3">{e.comment || ''}</td>
                                    <td className="py-1 pr-3 font-mono">{e.timeout || ''}</td>
                                    <td className="py-1 text-mk-mute">{[e.dynamic ? 'динамич.' : '', e.disabled ? 'отключена' : ''].filter(Boolean).join(', ')}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                            {ents.length > SHOW_ROWS && (
                              <div className="text-xs text-mk-mute py-1">
                                Показано {SHOW_ROWS} из {ents.length}; в файлы CSV и .rsc попадают все записи.
                              </div>
                            )}
                          </div>
                        )}
                      </>
                    )}

                    {(kind === 'plan' || kind === 'done') && r.lines.length > 0 && (
                      <pre className="text-[11px] font-mono bg-mk-bg p-2 rounded overflow-auto max-h-64">{r.lines.join('\n')}</pre>
                    )}
                    {kind === 'done' && r.undo.length > 0 && (
                      <button
                        type="button"
                        className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10"
                        onClick={() => exportUndo(r)}
                      >
                        Скачать откат (.rsc)
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {kind === 'summary' && knownLists.length === 0 && results && (
        <p className="text-xs text-mk-mute">Address-листов на выбранных устройствах нет.</p>
      )}
    </div>
  );
}
