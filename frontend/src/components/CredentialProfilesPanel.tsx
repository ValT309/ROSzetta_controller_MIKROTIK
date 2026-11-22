import { FormEvent, useEffect, useState } from 'react';
import { BookKey, Trash2 } from 'lucide-react';
import { api } from '@/api/client';

interface Profile {
  id: number;
  name: string;
  username: string;
  created_at: string | null;
}

export default function CredentialProfilesPanel() {
  const [items, setItems] = useState<Profile[]>([]);
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [pwd, setPwd] = useState('');
  const [pwd2, setPwd2] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const load = () =>
    api.get<Profile[]>('/credentials').then((r) => setItems(r.data)).catch(() => {});

  useEffect(() => { load(); }, []);

  const errText = (ex: any, fallback: string) => {
    const d = ex?.response?.data?.detail;
    return typeof d === 'string' ? d : fallback;
  };

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setMsg(null);
    if (pwd !== pwd2) { setMsg({ kind: 'err', text: 'Пароли не совпадают' }); return; }
    setBusy(true);
    try {
      await api.post('/credentials', { name: name.trim(), username: username.trim(), password: pwd });
      setName(''); setUsername(''); setPwd(''); setPwd2('');
      setMsg({ kind: 'ok', text: 'Учётная запись сохранена' });
      await load();
    } catch (ex) {
      setMsg({ kind: 'err', text: errText(ex, 'Не удалось сохранить') });
    } finally {
      setBusy(false);
    }
  };

  const remove = async (p: Profile) => {
    if (!window.confirm(`Удалить «${p.name}»? Уже добавленные устройства продолжат работать.`)) return;
    setMsg(null);
    try {
      await api.delete(`/credentials/${p.id}`);
      await load();
    } catch (ex) {
      setMsg({ kind: 'err', text: errText(ex, 'Не удалось удалить') });
    }
  };

  return (
    <div className="card space-y-3">
      <div className="flex items-center gap-2">
        <BookKey size={14} className="text-mk-accent2" />
        <h3 className="text-sm font-semibold">Сохранённые учётные записи</h3>
      </div>
      <p className="text-xs text-mk-mute">
        Используются при добавлении устройств: выбираете запись, и вводить логин и пароль не нужно.
        Пароль хранится зашифрованным и обратно не показывается.
      </p>

      {items.length > 0 && (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-mk-mute">
              <th className="py-1 pr-3">Название</th>
              <th className="py-1 pr-3">Логин</th>
              <th className="py-1"></th>
            </tr>
          </thead>
          <tbody>
            {items.map((p) => (
              <tr key={p.id} className="border-t border-white/5">
                <td className="py-1.5 pr-3">{p.name}</td>
                <td className="py-1.5 pr-3 font-mono text-xs">{p.username}</td>
                <td className="py-1.5 text-right">
                  <button
                    type="button" title="Удалить"
                    className="text-xs px-2 py-1 rounded border border-white/10 hover:bg-white/10"
                    onClick={() => remove(p)}
                  >
                    <Trash2 size={12} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <form onSubmit={add} className="grid grid-cols-1 md:grid-cols-5 gap-2 items-end" autoComplete="off">
        <div>
          <label className="text-xs text-mk-mute">Название</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Контроллер ROSzetta" required />
        </div>
        <div>
          <label className="text-xs text-mk-mute">Логин</label>
          <input className="input" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div>
          <label className="text-xs text-mk-mute">Пароль</label>
          <input
            className="input" type="password" autoComplete="new-password" spellCheck={false}
            name="roszetta-profile-password" value={pwd} onChange={(e) => setPwd(e.target.value)} required
          />
        </div>
        <div>
          <label className="text-xs text-mk-mute">Повторите пароль</label>
          <input
            className="input" type="password" autoComplete="new-password" spellCheck={false}
            name="roszetta-profile-password2" value={pwd2} onChange={(e) => setPwd2(e.target.value)} required
          />
        </div>
        <button className="btn-primary !text-xs" disabled={busy}>Сохранить</button>
      </form>

      {msg && (
        <div className={`text-sm ${msg.kind === 'ok' ? 'text-mk-ok' : 'text-mk-err'}`}>{msg.text}</div>
      )}
    </div>
  );
}
