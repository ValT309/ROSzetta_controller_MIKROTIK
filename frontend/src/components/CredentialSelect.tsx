import { useEffect, useState } from 'react';
import { api } from '@/api/client';

interface Profile {
  id: number;
  name: string;
  username: string;
}

/** Выбор сохранённой учётной записи в форме устройства. Если записей нет, не показывается. */
export default function CredentialSelect({
  value, onChange,
}: { value: number | null; onChange: (id: number | null) => void }) {
  const [items, setItems] = useState<Profile[]>([]);

  useEffect(() => {
    api.get<Profile[]>('/credentials').then((r) => setItems(r.data)).catch(() => {});
  }, []);

  if (!items.length) return null;
  return (
    <div>
      <label className="text-xs text-mk-mute">Учётная запись</label>
      <select
        className="input"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value ? Number(e.target.value) : null)}
      >
        <option value="">Ввести вручную</option>
        {items.map((c) => (
          <option key={c.id} value={c.id}>{c.name} ({c.username})</option>
        ))}
      </select>
    </div>
  );
}
