import { Monitor } from 'lucide-react';

const HOST_RE = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/;

/** Ссылка winbox://адрес: открывает WinBox на ПК пользователя (нужен обработчик, см. установщик). */
export default function WinboxButton({ host, className = '' }: { host: string; className?: string }) {
  if (!HOST_RE.test(host)) {
    return (
      <span className={`btn-ghost !py-0.5 !px-1.5 inline-flex items-center opacity-40 ${className}`} title="Для этого адреса ссылка WinBox недоступна">
        <Monitor size={12} />
      </span>
    );
  }
  return (
    <a
      href={`winbox://${host}`}
      className={`btn-ghost !py-0.5 !px-1.5 inline-flex items-center ${className}`}
      title="Открыть в WinBox"
      onClick={(e) => e.stopPropagation()}
    >
      <Monitor size={12} />
    </a>
  );
}
