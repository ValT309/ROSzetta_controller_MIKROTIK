import { useEffect, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { api, Device } from '@/api/client';

export const NO_GROUP = 'Без группы';

export type GroupRow =
  | { kind: 'group'; name: string; count: number; down: number; collapsed: boolean }
  | { kind: 'device'; device: Device; index: number };

/** Свёрнутые группы запоминаются в браузере (отдельно для роутеров и свичей). */
export function useCollapsedGroups(key: string) {
  const storageKey = `roszetta.collapsed.${key}`;
  const [collapsed, setCollapsed] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem(storageKey);
      return new Set<string>(raw ? JSON.parse(raw) : []);
    } catch {
      return new Set<string>();
    }
  });
  const toggle = (name: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      try { localStorage.setItem(storageKey, JSON.stringify(Array.from(next))); } catch { /* ignore */ }
      return next;
    });
  };
  return { collapsed, toggle };
}

/** Плоский список строк: заголовок группы, затем её устройства. Без групп возвращает обычный список. */
export function buildGroupRows(list: Device[], collapsed: Set<string>): GroupRow[] {
  const hasGroups = list.some((d) => (d.group_name || '').trim());
  if (!hasGroups) {
    return list.map((device, i): GroupRow => ({ kind: 'device', device, index: i + 1 }));
  }
  const map = new Map<string, Device[]>();
  for (const d of list) {
    const g = (d.group_name || '').trim() || NO_GROUP;
    if (!map.has(g)) map.set(g, []);
    map.get(g)!.push(d);
  }
  const names = Array.from(map.keys()).sort((a, b) => {
    if (a === NO_GROUP) return 1;
    if (b === NO_GROUP) return -1;
    return a.localeCompare(b, 'ru');
  });
  const rows: GroupRow[] = [];
  let index = 0;
  for (const name of names) {
    const devs = map.get(name)!;
    const isCollapsed = collapsed.has(name);
    rows.push({
      kind: 'group',
      name,
      count: devs.length,
      down: devs.filter((d) => d.status === 'down').length,
      collapsed: isCollapsed,
    });
    for (const device of devs) {
      index += 1;
      if (!isCollapsed) rows.push({ kind: 'device', device, index });
    }
  }
  return rows;
}

export function GroupHeaderRow(props: {
  colSpan: number;
  name: string;
  count: number;
  down: number;
  collapsed: boolean;
  onToggle: () => void;
}) {
  const Icon = props.collapsed ? ChevronRight : ChevronDown;
  return (
    <tr className="border-t border-mk-border bg-mk-panel2 cursor-pointer select-none" onClick={props.onToggle}>
      <td colSpan={props.colSpan} className="px-2 py-1.5">
        <span className="inline-flex items-center gap-2 text-xs font-semibold">
          <Icon size={14} className="text-mk-mute" />
          {props.name}
          <span className="text-mk-mute font-normal">({props.count})</span>
          {props.down > 0 && (
            <span className="text-mk-err font-normal">● недоступно: {props.down}</span>
          )}
        </span>
      </td>
    </tr>
  );
}

/** Выбор группы в форме устройства: существующая, «Без группы» или новая. */
export function GroupSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [options, setOptions] = useState<string[]>([]);
  const [custom, setCustom] = useState(false);

  useEffect(() => {
    api.get<Device[]>('/devices')
      .then((r) => {
        const set = new Set<string>();
        r.data.forEach((d) => { if ((d.group_name || '').trim()) set.add(d.group_name!.trim()); });
        setOptions(Array.from(set).sort((a, b) => a.localeCompare(b, 'ru')));
      })
      .catch(() => {});
  }, []);

  const known = options.includes(value);
  const showInput = custom || (value !== '' && !known);

  return (
    <div>
      <select
        className="input"
        value={showInput ? '__new' : value}
        onChange={(e) => {
          if (e.target.value === '__new') { setCustom(true); onChange(''); }
          else { setCustom(false); onChange(e.target.value); }
        }}
      >
        <option value="">Без группы</option>
        {options.map((g) => <option key={g} value={g}>{g}</option>)}
        <option value="__new">Новая группа…</option>
      </select>
      {showInput && (
        <input
          className="input mt-1"
          placeholder="Название группы"
          maxLength={128}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          autoFocus
        />
      )}
    </div>
  );
}

/** Кнопки «выбрать всю группу» для панелей с галочками устройств. */
export function GroupChips({ devices, selected, setSelected }: {
  devices: { id: number; group_name?: string | null }[];
  selected: number[];
  setSelected: (ids: number[]) => void;
}) {
  const groups = new Map<string, number[]>();
  for (const d of devices) {
    const g = (d.group_name || '').trim();
    if (!g) continue;
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)!.push(d.id);
  }
  if (groups.size === 0) return null;
  const names = Array.from(groups.keys()).sort((a, b) => a.localeCompare(b, 'ru'));
  return (
    <div className="flex flex-wrap items-center gap-1 mb-1">
      <span className="text-xs text-mk-mute">Группы:</span>
      {names.map((g) => {
        const ids = groups.get(g)!;
        const all = ids.every((id) => selected.includes(id));
        return (
          <button
            key={g}
            type="button"
            className={`text-xs px-2 py-0.5 rounded border ${
              all ? 'border-mk-accent2 text-mk-accent2' : 'border-white/10 text-mk-mute hover:bg-white/10'
            }`}
            onClick={() =>
              setSelected(
                all
                  ? selected.filter((id) => !ids.includes(id))
                  : Array.from(new Set([...selected, ...ids])),
              )
            }
          >
            {g} ({ids.length})
          </button>
        );
      })}
    </div>
  );
}
