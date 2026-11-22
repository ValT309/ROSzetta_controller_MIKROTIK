import { useState } from 'react';
import { Code } from 'lucide-react';
import { api } from '@/api/client';

interface Item {
  n: number;
  source: string;
  api: string | null;
  path: string | null;
  command: string | null;
  notes: string[];
  warnings: string[];
  error: string | null;
  dangerous: boolean;
}

const EXAMPLE = `/ip firewall address-list add list=block address=203.0.113.5 comment="bad host"
/interface ethernet set [find default-name=ether1] disabled=yes
/ip route print where dst-address=0.0.0.0/0
/ip firewall address-list remove [find list=block]`;

function copyText(text: string): boolean {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* ниже запасной путь для http-страниц */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

export default function CliConverter({ onUse }: { onUse: (cmd: string) => void }) {
  const [text, setText] = useState('');
  const [items, setItems] = useState<Item[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<number | null>(null);

  const convert = async () => {
    setError(null);
    setItems(null);
    if (!text.trim()) { setError('Введите команды'); return; }
    setBusy(true);
    try {
      const r = await api.post<{ items: Item[] }>('/cli/convert', { text });
      setItems(r.data.items);
    } catch (ex: any) {
      const d = ex?.response?.data?.detail;
      setError(typeof d === 'string' ? d : 'Не удалось выполнить конвертацию');
    } finally {
      setBusy(false);
    }
  };

  const copy = (n: number, value: string) => {
    if (copyText(value)) {
      setCopied(n);
      setTimeout(() => setCopied(null), 1500);
    }
  };

  const okItems = (items ?? []).filter((i) => i.api);

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <Code size={14} className="text-mk-accent2" />
        <h3 className="text-sm font-semibold">Конвертер команд RouterOS: терминал → API</h3>
      </div>
      <p className="text-xs text-mk-mute">
        Вставьте команды из терминала (по одной в строке; перенос строки через «\»). Получите формат API:
        путь со слэшами, параметры key=value, условия после where. Результат можно подставить на вкладку CLI.
        Сама вкладка CLI понимает оба формата, поэтому конвертация нужна, чтобы увидеть, что именно уйдёт на роутер.
      </p>

      <textarea
        className="input font-mono text-xs h-36"
        value={text}
        placeholder={EXAMPLE}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
      />

      <div className="flex flex-wrap gap-2">
        <button type="button" className="btn-primary !text-xs" disabled={busy} onClick={convert}>
          {busy ? 'Конвертация…' : 'Конвертировать'}
        </button>
        <button type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10" onClick={() => setText(EXAMPLE)}>
          Пример
        </button>
        {okItems.length > 1 && (
          <button
            type="button" className="text-xs px-3 py-1.5 rounded border border-white/10 hover:bg-white/10"
            onClick={() => copy(-1, okItems.map((i) => i.api).join('\n'))}
          >
            {copied === -1 ? 'Скопировано' : 'Копировать всё'}
          </button>
        )}
      </div>

      {error && <div className="text-sm text-mk-err">{error}</div>}

      {items && (
        <div className="divide-y divide-white/5">
          {items.map((it) => (
            <div key={it.n} className="py-2 space-y-1.5">
              <div className="text-xs text-mk-mute font-mono whitespace-pre-wrap break-all">{it.source}</div>
              {it.api && (
                <>
                  <pre className="text-[12px] font-mono bg-mk-bg p-2 rounded overflow-auto whitespace-pre-wrap break-all">{it.api}</pre>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button" className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10"
                      onClick={() => copy(it.n, it.api!)}
                    >
                      {copied === it.n ? 'Скопировано' : 'Копировать'}
                    </button>
                    <button
                      type="button" className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10"
                      onClick={() => onUse(it.api!)}
                    >
                      В поле CLI
                    </button>
                    {it.dangerous && <span className="text-xs text-mk-warn">опасная команда: потребуется подтверждение</span>}
                  </div>
                </>
              )}
              {it.error && <div className="text-xs text-mk-err">✕ {it.error}</div>}
              {it.warnings.map((w, i) => <div key={`w${i}`} className="text-xs text-mk-warn">· {w}</div>)}
              {it.notes.map((w, i) => <div key={`n${i}`} className="text-xs text-mk-mute">· {w}</div>)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
