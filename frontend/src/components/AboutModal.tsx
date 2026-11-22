import { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import { api } from '@/api/client';

type VersionInfo = { name: string; version: string; modules?: Record<string,string>; history?: {version:string;changes:string[]}[] };

export default function AboutModal({ onClose }: { onClose: () => void }) {
  const [info, setInfo] = useState<VersionInfo | null>(null);

  useEffect(() => {
    api.get<VersionInfo>('/version')
      .then((r) => setInfo(r.data))
      .catch(() => {});
  }, []);

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="card w-full max-w-md relative" onClick={(e) => e.stopPropagation()}>
        <button
          className="absolute top-3 right-3 text-mk-mute hover:text-mk-text"
          onClick={onClose}
          aria-label="Закрыть"
        >
          <X size={18} />
        </button>
        <div className="flex items-center gap-3 mb-4">
          <img src="/mikrotik-logo.svg" alt="logo" className="w-12 h-12" />
          <div>
            <div className="text-lg font-semibold">{info?.name ?? 'ROSzetta'}</div>
            <div className="text-xs text-mk-mute font-mono">v{info?.version ?? '—'}</div>
          </div>
        </div>
        <div className="text-sm text-mk-text space-y-2">
          <div>Контроллер для управления MikroTik / RouterOS устройствами.</div>
          {info?.modules && <div className="border-t border-mk-border pt-3 space-y-1"><b>Версии модулей</b>{Object.entries(info.modules).map(([name,version])=><div key={name} className="flex justify-between gap-2"><span>{name}</span><span className="font-mono text-mk-mute">v{version}</span></div>)}</div>}
          {!!info?.history?.length && <div className="border-t border-mk-border pt-3 max-h-56 overflow-auto space-y-2"><b>История версий</b>{info.history.map(release=><div key={release.version}><span className="font-mono">v{release.version}</span>{release.changes.length?<ul className="list-disc pl-5 text-xs text-mk-mute">{release.changes.map(note=><li key={note}>{note}</li>)}</ul>:<p className="text-xs text-mk-mute">Предыдущая версия</p>}</div>)}</div>}
          <div className="pt-3 border-t border-mk-border">
            <div className="text-xs text-mk-mute uppercase tracking-wider mb-1">Разработчик</div>
            <div className="font-medium">Tarasyuk.VV</div>
          </div>
        </div>
      </div>
    </div>
  );
}
