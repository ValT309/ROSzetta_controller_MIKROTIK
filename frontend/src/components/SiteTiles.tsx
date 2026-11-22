import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, Device } from '@/api/client';
import { NO_GROUP } from '@/components/DeviceGroups';
import WinboxButton from '@/components/WinboxButton';

type Level = 'ok' | 'warn' | 'bad';

interface Site {
  name: string;
  devices: Device[];
  up: number;
  down: number;
  noNet: number;
  other: number;
  level: Level;
}

const TONE: Record<Level, string> = {
  ok: 'border-mk-ok/50',
  warn: 'border-mk-warn/60',
  bad: 'border-mk-err/70',
};
const NUM: Record<Level, string> = { ok: 'text-mk-ok', warn: 'text-mk-warn', bad: 'text-mk-err' };

function issuesOf(d: Device): string[] {
  const out: string[] = [];
  if (d.status === 'down') out.push('недоступно');
  if (d.abnormal_reboot) out.push('аварийный reboot');
  if (d.internet_ok === false) out.push('нет интернета');
  if (d.last_error && d.status !== 'down') out.push('ошибка опроса');
  return out;
}

export default function SiteTiles() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    const load = () => api.get<Device[]>('/devices').then((r) => setDevices(r.data)).catch(() => {});
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  const sites = useMemo<Site[]>(() => {
    const map = new Map<string, Device[]>();
    (devices ?? []).forEach((d) => {
      const g = (d.group_name || '').trim() || NO_GROUP;
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(d);
    });
    const rows: Site[] = Array.from(map, ([name, ds]) => {
      const down = ds.filter((d) => d.status === 'down').length;
      const noNet = ds.filter((d) => d.status !== 'down' && d.internet_ok === false).length;
      const other = ds.filter(
        (d) => d.status !== 'down' && d.internet_ok !== false && (d.abnormal_reboot || d.last_error),
      ).length;
      return {
        name, devices: ds, down, noNet, other,
        up: ds.filter((d) => d.status === 'up').length,
        level: down ? 'bad' : noNet || other ? 'warn' : 'ok',
      };
    });
    rows.sort(
      (a, b) =>
        (a.name === NO_GROUP ? 1 : 0) - (b.name === NO_GROUP ? 1 : 0) ||
        a.name.localeCompare(b.name, 'ru'),
    );
    return rows;
  }, [devices]);

  const sel = sites.find((s) => s.name === selected) ?? null;

  if (!devices) return <div className="text-xs text-mk-mute">Загрузка…</div>;
  if (!sites.length) return <div className="text-sm text-mk-mute">Нет устройств</div>;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-6 gap-3">
        {sites.map((s) => (
          <button
            key={s.name}
            type="button"
            onClick={() => setSelected(selected === s.name ? null : s.name)}
            className={`card text-left aspect-square flex flex-col justify-between border-2 ${TONE[s.level]} ${
              selected === s.name ? 'ring-2 ring-mk-accent' : ''
            } hover:bg-white/[0.03]`}
          >
            <div className="text-lg sm:text-[22px] font-semibold leading-tight break-words overflow-hidden max-h-[3.6em]" title={s.name}>
              {s.name}
            </div>
            <div>
              <div className={`text-4xl font-semibold ${NUM[s.level]}`}>
                {s.up}
                <span className="text-lg text-mk-mute"> / {s.devices.length}</span>
              </div>
              <div className="text-[11px] mt-1 space-y-0.5 min-h-[2.6em]">
                {s.down > 0 && <div className="text-mk-err">недоступно: {s.down}</div>}
                {s.noNet > 0 && <div className="text-mk-warn">нет интернета: {s.noNet}</div>}
                {s.other > 0 && <div className="text-mk-warn">с ошибками: {s.other}</div>}
                {s.level === 'ok' && <div className="text-mk-mute">всё в порядке</div>}
              </div>
            </div>
          </button>
        ))}
      </div>

      {sites.length === 1 && sites[0].name === NO_GROUP && (
        <p className="text-xs text-mk-mute">
          Участки задаются группой устройства (Изменить → Группа): после назначения групп устройства
          разделятся на отдельные квадраты.
        </p>
      )}

      {sel && (
        <div className="card p-0 overflow-hidden">
          <div className="px-3 py-2 border-b border-mk-border text-sm font-semibold">
            {sel.name} ({sel.devices.length})
          </div>
          <table className="w-full text-[13px]">
            <tbody>
              {sel.devices.map((d) => {
                const issues = issuesOf(d);
                return (
                  <tr key={d.id} className="border-t border-mk-border first:border-t-0 hover:bg-mk-panel2/40">
                    <td className="px-2 py-1 w-5">
                      <span className={`inline-block w-2 h-2 rounded-full ${
                        d.status === 'up' ? 'bg-mk-ok' : d.status === 'down' ? 'bg-mk-err' : 'bg-mk-mute'
                      }`} />
                    </td>
                    <td className="px-2 py-1">
                      <Link to={`/devices/${d.id}`} className="text-mk-accent2 hover:underline">
                        {d.identity || d.name}
                      </Link>
                    </td>
                    <td className="px-2 py-1 text-mk-mute">{d.kind === 'switch' ? 'свич' : 'роутер'}</td>
                    <td className="px-2 py-1 text-mk-mute font-mono">{d.host}</td>
                    <td className="px-2 py-1 text-mk-mute">{d.model || '—'}</td>
                    <td className="px-2 py-1 text-mk-warn text-xs">{issues.join(', ')}</td>
                    <td className="px-2 py-1 text-right"><WinboxButton host={d.host} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
