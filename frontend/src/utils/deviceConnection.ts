// Standard ports follow the user's TLS toggle. Explicit custom ports are preserved.
export function portForTLS(port: number, tls: boolean): number {
  return port === 8728 || port === 8729 ? (tls ? 8729 : 8728) : port;
}
export function normalizePin(value: string): string {
  return value.trim().toLowerCase().replace(/^sha-?256\s*[:=]?\s*/, '').replace(/[\s:]/g, '');
}
export function connectionError(err: unknown): string {
  const detail=(err as {response?:{data?:{detail?:unknown}}})?.response?.data?.detail;
  return typeof detail==='string'?detail:'Проверьте параметры подключения и отпечаток сертификата';
}
