type Props = {size?: number; className?: string};

/** WAN reachability, not Wi-Fi. No change to the monitoring logic. */
export function InternetOn({size=16, className}: Props) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} role="img" aria-label="Интернет доступен">
    <circle cx="12" cy="12" r="9.5"/><ellipse cx="12" cy="12" rx="4.2" ry="9.5"/><path d="M2.5 12h19"/>
  </svg>;
}
export function InternetOff({size=16, className}: Props) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} role="img" aria-label="Нет интернета">
    <path d="M8 3.4a9.5 9.5 0 0 1 12.6 12.6M16 20.6A9.5 9.5 0 0 1 3.4 8M12 2.5c2.2 2.4 4 5.3 4.2 8.7M12 21.5C9.8 19.1 8 16.2 7.8 12.8M2.5 12h6.3m6.4 0h6.3M3 3l18 18"/>
  </svg>;
}
