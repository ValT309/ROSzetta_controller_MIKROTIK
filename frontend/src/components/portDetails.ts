import type { InterfaceInfo } from '@/api/client';

export function isWiredPort(it: InterfaceInfo): boolean {
  return /^(ether|sfp|qsfp)/i.test((it.type || '').trim());
}

export function findPort(interfaces: InterfaceInfo[], baseName: string): InterfaceInfo | undefined {
  const base = baseName.toLowerCase();
  const wired = interfaces.filter(isWiredPort);
  const byDefault = wired.filter(i=>i.default_name?.toLowerCase()===base);
  if (byDefault.length) return byDefault.length===1?byDefault[0]:undefined;
  // Legacy API fallback only if factory identity is unavailable.
  const candidates = wired.filter(i=>!i.default_name);
  const exact = candidates.filter(i=>i.name.toLowerCase()===base);
  if (exact.length) return exact.length===1?exact[0]:undefined;
  const prefix = candidates.filter(i=>i.name.toLowerCase().startsWith(base) && /^[\s\-_.:]/.test(i.name.slice(base.length)));
  return prefix.length===1?prefix[0]:undefined;
}

export function portState(it?: InterfaceInfo): string {
  if (!it) return 'Нет данных';
  if (it.disabled) return 'Отключён';
  return it.running ? 'Link UP' : 'Link Down';
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n<0) return '—';
  const units=['Б','КиБ','МиБ','ГиБ','ТиБ','ПиБ'];
  let i=0;
  while (n>=1024 && i<units.length-1) {n/=1024;i++;}
  return `${i?n.toFixed(1):n} ${units[i]}`;
}

export type TrafficPoint = { at: number; rx: number | null; tx: number | null; seconds: number | null };

function difference(before?: string | null, after?: string | null, seconds?: number): number | null {
  if (!before || !after || !/^\d+$/.test(before) || !/^\d+$/.test(after) || !seconds) return null;
  const delta = BigInt(after) - BigInt(before);
  if (delta < 0n) return null;
  const rate = Number(delta) * 8 / seconds;
  return Number.isFinite(rate) ? rate : null;
}

/** Average bits/s between two real, server-timestamped byte counter samples. */
export function trafficPoint(before: InterfaceInfo | undefined, now: InterfaceInfo): TrafficPoint | null {
  const at = now.sampled_at_ms;
  if (typeof at !== 'number' || !Number.isFinite(at)) return null;
  const empty: TrafficPoint = {at,rx:null,tx:null,seconds:null};
  if (!before || typeof before.sampled_at_ms !== 'number' || !now.running || !before.running || now.disabled || before.disabled) return empty;
  if (now.name !== before.name || (now.default_name ?? null) !== (before.default_name ?? null) || (now.mac_address ?? null)!==(before.mac_address ?? null)) return empty;
  const seconds=(at-before.sampled_at_ms)/1000;
  if (!Number.isFinite(seconds) || seconds<1 || seconds>120) return empty;
  if (typeof now.uptime_seconds==='number' && typeof before.uptime_seconds==='number' && (now.uptime_seconds < before.uptime_seconds || now.uptime_seconds-before.uptime_seconds < seconds-5)) return empty;
  const oldDown=before.diagnostics?.['link-downs'], newDown=now.diagnostics?.['link-downs'];
  if (oldDown!==undefined && newDown!==undefined && oldDown!==newDown) return empty;
  const rx=difference(before.rx_counter,now.rx_counter,seconds), tx=difference(before.tx_counter,now.tx_counter,seconds);
  return {at,rx,tx,seconds:rx===null&&tx===null?null:seconds};
}

export function formatRate(rate: number | null | undefined): string {
  if (typeof rate!=='number' || !Number.isFinite(rate) || rate<0) return '—';
  const units=['бит/с','кбит/с','Мбит/с','Гбит/с','Тбит/с'];
  let i=0;
  while (rate>=1000&&i<units.length-1) {rate/=1000;i++;}
  return `${rate.toLocaleString('ru-RU',{maximumFractionDigits:i?2:0})} ${units[i]}`;
}

/** SVG path, with gaps where samples are missing; no interpolated traffic. */
export function trafficPath(points: TrafficPoint[], key: 'rx'|'tx', max: number, width=560, height=100): string {
  if (!points.length || !Number.isFinite(max) || max<=0) return '';
  const start=points[0].at, span=Math.max(points[points.length-1].at-start,1);
  let pen=false, lastAt: number | null=null;
  return points.map(p=>{
    const n=p[key];
    if (n===null||!Number.isFinite(n)||n<0) {pen=false;lastAt=null;return '';}
    if(lastAt!==null&&p.at-lastAt>120000) pen=false;
    const x=Math.max(0,Math.min(width,(p.at-start)/span*width)), y=Math.max(0,Math.min(height,height*(1-n/max)));
    const cmd=`${pen?'L':'M'}${x.toFixed(2)} ${y.toFixed(2)}`;pen=true;lastAt=p.at;return cmd;
  }).filter(Boolean).join(' ');
}

const diagnosticGroups = [
  {title:'Линк', fields:[['full-duplex','Duplex'],['auto-negotiation','Auto-negotiation']]},
  {title:'SFP / QSFP', fields:[['sfp-module-present','Модуль установлен'],['sfp-vendor-name','Производитель'],['sfp-vendor-part-number','Модель модуля'],['sfp-temperature','Температура, °C'],['sfp-supply-voltage','Напряжение, В'],['sfp-rx-power','Оптическая мощность RX, dBm'],['sfp-tx-power','Оптическая мощность TX, dBm'],['sfp-tx-bias-current','Ток лазера, мА'],['sfp-rx-loss','Потеря сигнала RX'],['sfp-tx-fault','Ошибка передатчика'],['qsfp-temperature','Температура QSFP, °C'],['qsfp-rx-power','QSFP RX, dBm'],['qsfp-tx-power','QSFP TX, dBm']]},
  {title:'PoE-Out', fields:[['poe-out','Режим'],['poe-out-status','Состояние питания'],['poe-out-voltage','Напряжение, В'],['poe-out-current','Ток, мА'],['poe-out-power','Мощность, Вт']]},
  {title:'Ошибки и события (накопленные)', fields:[['rx-error','RX errors'],['tx-error','TX errors'],['rx-fcs-error','RX FCS errors'],['rx-align-error','RX alignment errors'],['rx-code-error','RX code errors'],['rx-error-events','RX error events'],['rx-overflow','RX overflow'],['rx-drop','RX drops'],['tx-drop','TX drops'],['tx-collision','TX collisions'],['link-downs','Падения линка']]},
];

export function getPortDiagnostics(it?: InterfaceInfo) {
  const data=it?.diagnostics??{};
  return diagnosticGroups.map(g=>({title:g.title,rows:g.fields.filter(([key])=>data[key]!==undefined&&data[key]!=='').map(([key,label])=>[label,data[key]] as [string,string])})).filter(g=>g.rows.length>0);
}
